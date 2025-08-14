import trimesh
import numpy as np
import nav_utils
import visualizer
import pathfinder

if __name__ == "__main__":
    
    # --- НАСТРОЙКИ ---
    OBJ_FILE_PATH = "43_12_wow.obj" 
    GRID_RESOLUTION = 128

    # --- ШАГ 1: ЗАГРУЗКА ---
    print(f"[Main] Пытаюсь загрузить геометрию из файла: {OBJ_FILE_PATH}")
    try:
        mesh = trimesh.load(OBJ_FILE_PATH, force='mesh')
        mesh = mesh.split()[0] if isinstance(mesh, trimesh.Scene) else mesh
        print("[Main] УСПЕХ! Геометрия успешно загружена через trimesh.")
    except Exception as e:
        print(f"[Main] Ошибка при загрузке файла: {e}")
        mesh = None

    if mesh:
        # --- ШАГ 2: СОЗДАНИЕ СЕТКИ ---
        nav_grid, _, _, _ = nav_utils.create_navigation_grid_fast(
            mesh, GRID_RESOLUTION, GRID_RESOLUTION
        )
        
        if nav_grid is not None:
            # --- ШАГ 3: ОПРЕДЕЛЕНИЕ ТОЧЕК И ПОИСК ПУТИ ---
            
            # Жестко задаем координаты в сетке. Можете менять эти цифры.
            start_grid = (30, 30)
            end_grid = (70, 80)
            
            print(f"\n[Main] Заданы точки: СТАРТ={start_grid}, ФИНИШ={end_grid}")
            
            # Извлекаем мировые 3D-координаты для этих точек, чтобы нарисовать шары
            start_world = nav_grid[start_grid[0], start_grid[1], 1:4]
            end_world = nav_grid[end_grid[0], end_grid[1], 1:4]
            
            path = None # Изначально пути нет
            
            # Проверяем проходимость точек
            start_is_walkable = nav_grid[start_grid[0], start_grid[1], 0] == 1.0
            end_is_walkable = nav_grid[end_grid[0], end_grid[1], 0] == 1.0

            if start_is_walkable and end_is_walkable:
                print("[Main] Обе точки проходимы, запускаю поиск пути...")
                path = pathfinder.astar_pathfind(nav_grid, start_grid, end_grid)
            else:
                print("[Main] ОШИБКА: Одна или обе точки непроходимы. Путь не будет искаться.")
                if not start_is_walkable: 
                    print(f"  - Стартовая точка {start_grid} непроходима.")
                if not end_is_walkable: 
                    print(f"  - Конечная точка {end_grid} непроходима.")
                
            # --- ШАГ 4: ФИНАЛЬНАЯ ВИЗУАЛИЗАЦИЯ ---
            # Вызываем визуализатор, который теперь ГАРАНТИРОВАННО покажет результат
            visualizer.visualize_result_3d(nav_grid, mesh, path, start_world, end_world)

    print("\n[Main] Программа завершена.")