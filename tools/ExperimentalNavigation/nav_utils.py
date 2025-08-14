# nav_utils.py

import numpy as np
import time
import trimesh

def create_navigation_grid_fast(mesh, grid_resolution_x, grid_resolution_z):
    print("\n[Nav Utils] Начинаю создание навигационной сетки (быстрый метод)...")
    
    min_coords, max_coords = mesh.bounds
    world_size_x = max_coords[0] - min_coords[0]
    world_size_y = max_coords[1] - min_coords[1]
    
    cell_size_x = world_size_x / grid_resolution_x
    cell_size_y = world_size_y / grid_resolution_z

    print(f"[Nav Utils] Размер тайла: {world_size_x:.2f} x {world_size_y:.2f} игровых единиц.")
    print(f"[Nav Utils] Разрешение сетки: {grid_resolution_x} x {grid_resolution_z} ячеек.")
    print(f"[Nav Utils] Размер одной ячейки: {cell_size_x:.2f} x {cell_size_y:.2f} игровых единиц.")

    x_coords = np.linspace(min_coords[0] + cell_size_x/2, max_coords[0] - cell_size_x/2, grid_resolution_x)
    y_coords = np.linspace(min_coords[1] + cell_size_y/2, max_coords[1] - cell_size_y/2, grid_resolution_z)
    grid_x, grid_y = np.meshgrid(x_coords, y_coords)
    
    ray_origins = np.stack([grid_x.ravel(), grid_y.ravel(), np.full_like(grid_x.ravel(), 9999.0)], axis=1)
    ray_directions = np.tile([0, 0, -1], (ray_origins.shape[0], 1))

    start_time = time.time()
    locations, index_ray, index_tri = mesh.ray.intersects_location(
        ray_origins=ray_origins,
        ray_directions=ray_directions
    )
    end_time = time.time()
    print(f"[Nav Utils] Трассировка {len(ray_origins)} лучей завершена за {end_time - start_time:.4f} секунд.")

    # Создаем сетку, где будет храниться 4 значения:
    # 0: проходимость, 1: world_X, 2: world_Y, 3: world_Z
    nav_grid = np.zeros((grid_resolution_x, grid_resolution_z, 4), dtype=np.float32)
    
    normals = mesh.face_normals[index_tri]
    slope_dots = np.abs(np.dot(normals, [0, 0, 1]))
    slope_angles_deg = np.degrees(np.arccos(slope_dots))

    MAX_SLOPE_DEGREES = 50
    is_walkable = slope_angles_deg < MAX_SLOPE_DEGREES
    
    # Конвертируем растровые индексы лучей в 2D индексы сетки
    grid_indices_2d = np.unravel_index(index_ray, (grid_resolution_z, grid_resolution_x))

    # Заполняем мировые координаты для КАЖДОЙ точки пересечения
    nav_grid[grid_indices_2d[1], grid_indices_2d[0], 1] = locations[:, 0] # World X
    nav_grid[grid_indices_2d[1], grid_indices_2d[0], 2] = locations[:, 1] # World Y
    nav_grid[grid_indices_2d[1], grid_indices_2d[0], 3] = locations[:, 2] # World Z (высота)
    
    # Заполняем проходимость
    nav_grid[grid_indices_2d[1], grid_indices_2d[0], 0] = is_walkable.astype(np.float32)

    return nav_grid, min_coords, cell_size_x, cell_size_y