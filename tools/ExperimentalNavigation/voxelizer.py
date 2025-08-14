# voxelizer.py

import numpy as np
import trimesh

def voxelize_mesh_advanced(mesh, resolution):
    print(f"\n[Voxelizer] Начинаю продвинутую вокселизацию с разрешением {resolution}...")
    
    # Шаг 1: Создаем "пусто/занято" сетку, как и раньше
    pitch = np.max(mesh.extents) / resolution
    solid_voxels = mesh.voxelized(pitch=pitch).fill().matrix
    
    # Шаг 2: Создаем новую сетку для навигации
    # 0 = воздух, 1 = стена/препятствие, 2 = проходимая земля
    nav_grid = np.zeros_like(solid_voxels, dtype=np.uint8)
    nav_grid[solid_voxels] = 1 # Помечаем все "твердое" как 1
    
    # Шаг 3: Ищем "проходимые" воксели
    # Находим все точки на границе между "воздухом" и "стеной"
    surface_indices = np.argwhere((nav_grid == 1) & (np.roll(nav_grid, 1, axis=2) == 0))
    
    if len(surface_indices) == 0:
        raise ValueError("Не найдено поверхностей в модели.")

    # Получаем нормали для каждой точки поверхности
    locations = surface_indices * pitch + mesh.bounds[0]
    _, _, face_indices = trimesh.proximity.closest_point(mesh, locations)
    normals = mesh.face_normals[face_indices]
    
    # Проверяем уклон
    vertical_vector = [0, 0, 1]
    dot_products = np.abs(np.dot(normals, vertical_vector))
    
    MAX_SLOPE_DEG = 50.0
    min_dot_product = np.cos(np.radians(MAX_SLOPE_DEG))
    
    is_walkable = dot_products > min_dot_product
    
    # Помечаем проходимые воксели в нашей сетке
    walkable_indices = tuple(surface_indices[is_walkable].T)
    nav_grid[walkable_indices] = 2

    print(f"[Voxelizer] Вокселизация завершена. Найдено {len(walkable_indices[0])} проходимых вокселей.")
    
    voxel_info = {
        'grid': nav_grid,
        'transform': trimesh.transformations.scale_and_translate(scale=pitch, translate=mesh.bounds[0])
    }
    return voxel_info