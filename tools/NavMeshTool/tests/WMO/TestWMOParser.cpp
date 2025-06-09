#include "core/WoWFiles/Parsers/WMO/WMOParser.h"
#include <gtest/gtest.h>
#include <filesystem>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>

// Helper to read a binary file into a vector. This is used by our FileProvider.
std::optional<std::vector<unsigned char>> read_file_into_buffer(const std::filesystem::path& path)
{
    if (!std::filesystem::exists(path))
    {
        // It's normal for some files (especially doodads) not to be found, so no warning here.
        return std::nullopt;
    }

    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file)
    {
        // But if the file exists and we can't open it, that's a problem.
        std::cerr << "Failed to open file: " << path << std::endl;
        return std::nullopt;
    }

    const std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<unsigned char> buffer(static_cast<size_t>(size));
    if (file.read(reinterpret_cast<char*>(buffer.data()), size))
    {
        return buffer;
    }

    std::cerr << "Failed to read file into buffer: " << path << std::endl;
    return std::nullopt;
}

// Helper function to write WmoData to a .obj file for visualization in Blender/3ds Max
void save_to_obj(const std::string& filepath, const NavMeshTool::WMO::WmoData& data)
{
    std::ofstream obj_file(filepath);
    if (!obj_file)
    {
        return;
    }

    // Write vertices
    for (const auto& v : data.vertices)
    {
        obj_file << "v " << v.x << " " << v.y << " " << v.z << "\n";
    }

    // Write faces (indices)
    // .obj files use 1-based indexing
    for (size_t i = 0; i < data.indices.size(); i += 3)
    {
        obj_file << "f " << data.indices[i] + 1 << " " << data.indices[i + 1] + 1 << " " << data.indices[i + 2] + 1
                 << "\n";
    }
}

// Common setup for all Black Temple tests
class TestWMOParser_BlackTemple : public ::testing::Test
{
   protected:
    std::optional<NavMeshTool::WMO::WmoData> wmo_data_opt;

    void SetUp() override
    {
        const std::filesystem::path data_dir = "Data";
        const std::string root_wmo_name = "Blacktemple.wmo";
        const auto root_wmo_path = data_dir / root_wmo_name;

        if (!std::filesystem::exists(root_wmo_path))
        {
            GTEST_SKIP() << "Root WMO file not found, skipping tests: " << root_wmo_path.string();
            return;
        }

        auto root_buffer_opt = read_file_into_buffer(root_wmo_path);
        if (!root_buffer_opt)
        {
            GTEST_FAIL() << "Could not read root WMO file into buffer: " << root_wmo_path.string();
            return;
        }

        // This lambda acts as our FileProvider, loading dependent files from the Data directory on demand.
        auto file_provider = [&](const std::string& filename) -> std::optional<std::vector<unsigned char>>
        {
            // The parser requests files with WoW-style paths. We need to find them in our flat "Data" directory.
            std::filesystem::path fs_path(filename);
            return read_file_into_buffer(data_dir / fs_path.filename());
        };

        NavMeshTool::WMO::Parser parser;
        wmo_data_opt = parser.parse(root_wmo_name, *root_buffer_opt, file_provider);
    }
};

TEST_F(TestWMOParser_BlackTemple, RootFileIsParsedSuccessfully)
{
    ASSERT_TRUE(wmo_data_opt.has_value()) << "WMOParser failed to parse the file.";
}

TEST_F(TestWMOParser_BlackTemple, GroupInfo)
{
    ASSERT_TRUE(wmo_data_opt.has_value());
    const auto& wmo_data = wmo_data_opt.value();

    ASSERT_EQ(wmo_data.header.nGroups, 49) << "Expected 49 groups based on MOHD.nGroups.";
    ASSERT_EQ(wmo_data.group_info.size(), 49) << "Expected 49 group info entries.";

    auto get_group_name = [&](int index)
    {
        const auto& info = wmo_data.group_info[index];
        if (info.name_offset == -1 || info.name_offset >= wmo_data.group_names_blob.size()) return std::string("N/A");
        return std::string(&wmo_data.group_names_blob[info.name_offset]);
    };

    EXPECT_EQ(get_group_name(40), "Den of Mortal Delights");
    EXPECT_EQ(wmo_data.group_info[40].flags, 0x000420C0);

    EXPECT_EQ(get_group_name(42), "Den of Mortal Delights");
    EXPECT_EQ(wmo_data.group_info[42].flags, 0x00002040);

    EXPECT_EQ(get_group_name(44), "Den of Mortal Delights");
    EXPECT_EQ(wmo_data.group_info[44].flags, 0x00002040);

    EXPECT_EQ(get_group_name(46), "Chamber of Command");
    EXPECT_EQ(wmo_data.group_info[46].flags, 0x000400C8);

    EXPECT_EQ(get_group_name(41), "balcony");
    EXPECT_EQ(wmo_data.group_info[41].flags, 0x00002040);

    EXPECT_EQ(get_group_name(0), "N/A");
    EXPECT_EQ(wmo_data.group_info[0].flags, 0x00002000);

    EXPECT_EQ(get_group_name(2), "hall08");
    EXPECT_EQ(wmo_data.group_info[2].flags, 0x00042040);
}

TEST_F(TestWMOParser_BlackTemple, PortalInfo)
{
    ASSERT_TRUE(wmo_data_opt.has_value());
    const auto& wmo_data = wmo_data_opt.value();

    ASSERT_EQ(wmo_data.portal_vertices.size(), 318) << "Expected 318 portal vertices (MOPV).";
    ASSERT_EQ(wmo_data.portal_infos.size(), 78) << "Expected 78 portal definitions (MOPT).";
    ASSERT_EQ(wmo_data.portal_refs.size(), 132) << "Expected 132 portal relationships (MOPR).";

    const auto& ref0 = wmo_data.portal_refs[0];
    EXPECT_EQ(ref0.portal_index, 7);
    EXPECT_EQ(ref0.group_index, 8);
    EXPECT_EQ(ref0.side, -1);

    const auto& ref1 = wmo_data.portal_refs[1];
    EXPECT_EQ(ref1.portal_index, 8);
    EXPECT_EQ(ref1.group_index, 7);
    EXPECT_EQ(ref1.side, 1);

    const auto& ref128 = wmo_data.portal_refs[128];
    EXPECT_EQ(ref128.portal_index, 66);
    EXPECT_EQ(ref128.group_index, 5);
    EXPECT_EQ(ref128.side, 1);

    const auto& portal35_info = wmo_data.portal_infos[35];
    EXPECT_EQ(portal35_info.start_vertex_index, 140);
    EXPECT_EQ(portal35_info.count, 10);
}

TEST_F(TestWMOParser_BlackTemple, DoodadInfo)
{
    ASSERT_TRUE(wmo_data_opt.has_value());
    const auto& wmo_data = wmo_data_opt.value();

    ASSERT_EQ(wmo_data.doodad_sets.size(), 1) << "Expected 1 doodad set (MODS).";
    ASSERT_EQ(wmo_data.doodad_defs.size(), 3520) << "Expected 3520 doodad definitions (MODD).";
    ASSERT_FALSE(wmo_data.doodad_names_blob.empty()) << "Doodad names blob (MODN) should not be empty.";

    const auto& default_set = wmo_data.doodad_sets[0];
    const std::string expected_name = "Set_$DefaultGlobal";
    const std::string actual_name = std::string(default_set.name, strnlen(default_set.name, sizeof(default_set.name)));

    EXPECT_EQ(actual_name, expected_name) << "The doodad set name is incorrect.";
    EXPECT_EQ(default_set.first_instance_index, 0);
    EXPECT_EQ(default_set.num_doodads, 3520);
}

TEST_F(TestWMOParser_BlackTemple, Group48Header)
{
    ASSERT_TRUE(wmo_data_opt.has_value());
    const auto& wmo_data = wmo_data_opt.value();

    ASSERT_EQ(wmo_data.groups.size(), 49);

    const auto& group48 = wmo_data.groups[48];
    ASSERT_TRUE(group48.is_parsed) << "Group 48 should have been parsed successfully.";

    const auto& header = group48.header;
    EXPECT_EQ(header.flags, 0x000428C1);
    EXPECT_EQ(header.portal_start_index, 132);
    EXPECT_EQ(header.portal_count, 0);
    EXPECT_EQ(header.exteriorBatchCount, 30);
    EXPECT_EQ(header.liquid_type_or_flags, 15);
    EXPECT_EQ(header.wmo_group_id, 22502);
    EXPECT_FLOAT_EQ(header.bounding_box.min.x, -1143.3603515625f);
    EXPECT_FLOAT_EQ(header.bounding_box.max.z, 622.210693359375f);
}

TEST_F(TestWMOParser_BlackTemple, FinalGeometry)
{
    ASSERT_TRUE(wmo_data_opt.has_value()) << "Geometry was not generated after parsing.";
    const auto& geometry = wmo_data_opt.value();

    // These numbers represent the combined collision geometry from all groups.
    // Doodad geometry is not included in this specific test, but the parser does load it.
    // The exact numbers can change based on how collision geometry (BSP) is extracted vs. visual geometry.
    // These values are based on extracting triangles from the BSP leaves.
    EXPECT_EQ(geometry.vertices.size(), 204531);
    EXPECT_EQ(geometry.indices.size(), 663093);

    // As a final check, let's save the output to an .obj file.
    // This is useful for visual inspection in a 3D modeling program.
    save_to_obj("black_temple_combined.obj", geometry);
}
