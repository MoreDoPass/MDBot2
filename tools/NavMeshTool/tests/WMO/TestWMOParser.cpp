#include "core/WoWFiles/Parsers/WMO/WMOParser.h"
#include <gtest/gtest.h>
#include <filesystem>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>

// Helper function to write WmoGeometry to a .obj file for visualization
void save_to_obj(const std::string& filepath, const wow_files::wmo::WmoGeometry& geometry)
{
    std::ofstream obj_file(filepath);
    if (!obj_file)
    {
        // In a real application, handle this error more gracefully
        return;
    }

    // Write vertices
    for (const auto& v : geometry.vertices)
    {
        obj_file << "v " << v.x << " " << v.y << " " << v.z << "\n";
    }

    // Write faces (indices)
    // .obj files use 1-based indexing
    for (size_t i = 0; i < geometry.indices.size(); i += 3)
    {
        obj_file << "f " << geometry.indices[i] + 1 << " " << geometry.indices[i + 1] + 1 << " "
                 << geometry.indices[i + 2] + 1 << "\n";
    }
}

TEST(TestWMOParser, BlackTempleGroupInfo)
{
    // Path to the test data, assuming it's copied to the build directory's "Data" folder
    const std::filesystem::path data_dir = "Data";
    const auto root_wmo_path = data_dir / "Blacktemple.wmo";

    ASSERT_TRUE(std::filesystem::exists(root_wmo_path)) << "Root WMO file not found: " << root_wmo_path.string();

    // Parse the WMO with our C++ parser
    wow_files::wmo::WMOParser parser;
    const bool parse_success = parser.parse(root_wmo_path.string());

    ASSERT_TRUE(parse_success) << "WMOParser failed to parse the file.";

    const auto groups = parser.get_groups();

    // 1. Check the total number of groups from the MOHD header.
    ASSERT_EQ(groups.size(), 49) << "Expected 49 groups based on MOHD.nGroups.";

    // 2. Perform spot checks on specific groups to verify MOGI and MOGN parsing.
    // These values are taken from the python script's analysis of the file.

    // Groups 40, 42, 44 have the same name but group 40 has different flags.
    // This is a good test case.
    ASSERT_EQ(groups[40].name, "Den of Mortal Delights");
    EXPECT_EQ(groups[40].flags, 0x000420C0);

    ASSERT_EQ(groups[42].name, "Den of Mortal Delights");
    EXPECT_EQ(groups[42].flags, 0x00002040);

    ASSERT_EQ(groups[44].name, "Den of Mortal Delights");
    EXPECT_EQ(groups[44].flags, 0x00002040);

    // Check another distinct group for robustness
    ASSERT_EQ(groups[46].name, "Chamber of Command");
    EXPECT_EQ(groups[46].flags, 0x000400C8);

    // Check a group with a different name
    ASSERT_EQ(groups[41].name, "balcony");
    EXPECT_EQ(groups[41].flags, 0x00002040);

    // Check the first few groups, some of which may not have names.
    ASSERT_EQ(groups[0].name, "N/A");
    EXPECT_EQ(groups[0].flags, 0x00002000);

    ASSERT_EQ(groups[2].name, "hall08");
    EXPECT_EQ(groups[2].flags, 0x00042040);
}

TEST(TestWMOParser, BlackTemplePortalInfo)
{
    const std::filesystem::path data_dir = "Data";
    const auto root_wmo_path = data_dir / "Blacktemple.wmo";

    ASSERT_TRUE(std::filesystem::exists(root_wmo_path)) << "Root WMO file not found: " << root_wmo_path.string();

    wow_files::wmo::WMOParser parser;
    const bool parse_success = parser.parse(root_wmo_path.string());

    ASSERT_TRUE(parse_success) << "WMOParser failed to parse the file.";

    // 1. Check counts from MOHD header against parsed chunk sizes.
    const auto& portal_vertices = parser.get_portal_vertices();
    const auto& portal_infos = parser.get_portal_infos();
    const auto& portal_refs = parser.get_portal_refs();

    ASSERT_EQ(portal_vertices.size(), 318) << "Expected 318 portal vertices (MOPV).";
    ASSERT_EQ(portal_infos.size(), 78) << "Expected 78 portal definitions (MOPT).";
    ASSERT_EQ(portal_refs.size(), 132) << "Expected 132 portal relationships (MOPR).";

    // 2. Spot check some specific portal relationships from the log.
    // Ref 0: Portal 7 leads to Group 8 (side: -1)
    const auto& ref0 = portal_refs[0];
    EXPECT_EQ(ref0.portal_index, 7);
    EXPECT_EQ(ref0.group_index, 8);
    EXPECT_EQ(ref0.side, -1);

    // Ref 1: Portal 8 leads to Group 7 (side: 1)
    const auto& ref1 = portal_refs[1];
    EXPECT_EQ(ref1.portal_index, 8);
    EXPECT_EQ(ref1.group_index, 7);
    EXPECT_EQ(ref1.side, 1);

    // Ref 128: Portal 66 leads to Group 5 (side: 1)
    const auto& ref128 = portal_refs[128];
    EXPECT_EQ(ref128.portal_index, 66);
    EXPECT_EQ(ref128.group_index, 5);
    EXPECT_EQ(ref128.side, 1);

    // Check info for a portal from MOPT
    // Portal 35: Starts at vertex 140, uses 10 vertices.
    const auto& portal35_info = portal_infos[35];
    EXPECT_EQ(portal35_info.start_vertex_index, 140);
    EXPECT_EQ(portal35_info.count, 10);
}

TEST(TestWMOParser, BlackTempleDoodadInfo)
{
    const std::filesystem::path data_dir = "Data";
    const auto root_wmo_path = data_dir / "Blacktemple.wmo";

    ASSERT_TRUE(std::filesystem::exists(root_wmo_path)) << "Root WMO file not found: " << root_wmo_path.string();

    wow_files::wmo::WMOParser parser;
    const bool parse_success = parser.parse(root_wmo_path.string());

    ASSERT_TRUE(parse_success) << "WMOParser failed to parse the file.";

    // 1. Check counts against the log file.
    const auto& doodad_sets = parser.get_doodad_sets();
    const auto& doodad_defs = parser.get_doodad_defs();
    const auto& doodad_names_blob = parser.get_doodad_names_blob();

    ASSERT_EQ(doodad_sets.size(), 1) << "Expected 1 doodad set (MODS).";
    ASSERT_EQ(doodad_defs.size(), 3520) << "Expected 3520 doodad definitions (MODD).";

    // A simple check for the names blob - it shouldn't be empty.
    // A full check would involve parsing the blob, which is too complex for this test.
    ASSERT_FALSE(doodad_names_blob.empty()) << "Doodad names blob (MODN) should not be empty.";

    // 2. Spot check the contents of the single doodad set.
    const auto& default_set = doodad_sets[0];

    // The name in the file is null-padded. We should compare it carefully.
    const std::string expected_name = "Set_$DefaultGlobal";
    const std::string actual_name = std::string(default_set.name, strnlen(default_set.name, sizeof(default_set.name)));

    EXPECT_EQ(actual_name, expected_name) << "The doodad set name is incorrect.";
    EXPECT_EQ(default_set.first_instance_index, 0);
    EXPECT_EQ(default_set.num_doodads, 3520);
}

TEST(TestWMOParser, BlackTempleGroup48Header)
{
    const std::filesystem::path data_dir = "Data";
    const auto root_wmo_path = data_dir / "Blacktemple.wmo";

    ASSERT_TRUE(std::filesystem::exists(root_wmo_path)) << "Root WMO file not found: " << root_wmo_path.string();

    wow_files::wmo::WMOParser parser;
    const bool parse_success = parser.parse(root_wmo_path.string());

    ASSERT_TRUE(parse_success) << "WMOParser failed to parse the root file.";

    const auto& headers = parser.get_group_headers();

    // MOHD in Blacktemple.wmo says there are 49 groups.
    // The parser should have loaded headers for all of them.
    ASSERT_EQ(headers.size(), 49);

    // We are interested in group 48
    const auto& header = headers[48];

    // These values are taken from the python script's analysis of Blacktemple_048.wmo
    EXPECT_EQ(header.flags, 0x000428C1);
    EXPECT_EQ(header.portal_start_index, 132);
    EXPECT_EQ(header.portal_count, 0);
    EXPECT_EQ(header.exteriorBatchCount, 30);
    EXPECT_EQ(header.liquid_type_or_flags, 15);
    EXPECT_EQ(header.wmo_group_id, 22502);
    EXPECT_FLOAT_EQ(header.bounding_box.min.x, -1143.3603515625f);
    EXPECT_FLOAT_EQ(header.bounding_box.max.z, 622.210693359375f);
}

TEST(TestWMOParser, BlackTempleFinalGeometry)
{
    const std::filesystem::path data_dir = "Data";
    const auto root_wmo_path = data_dir / "Blacktemple.wmo";

    ASSERT_TRUE(std::filesystem::exists(root_wmo_path)) << "Root WMO file not found: " << root_wmo_path.string();

    wow_files::wmo::WMOParser parser;
    const bool parse_success = parser.parse(root_wmo_path.string());

    ASSERT_TRUE(parse_success) << "WMOParser failed to parse the root file.";

    const auto& geometry_opt = parser.get_geometry();
    ASSERT_TRUE(geometry_opt.has_value()) << "Geometry was not generated after parsing.";

    const auto& geometry = geometry_opt.value();

    // Final check for the combined collision geometry from all groups and doodads.
    EXPECT_EQ(geometry.vertices.size(), 204531);
    EXPECT_EQ(geometry.indices.size(), 663111);
}
