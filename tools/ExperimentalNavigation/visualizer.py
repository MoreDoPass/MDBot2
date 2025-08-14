# visualizer.py

import pyvista as pv
import numpy as np

def _get_walkable_points(grid):
    """Вспомогательная функция для получения 3D-координат проходимых ячеек."""
    walkable_indices = np.where(grid[:, :, 0] > 0)
    walkable_points = grid[walkable_indices[0], walkable_indices[1], 1:4]
    return walkable_points

def visualize_result_3d(grid, original_mesh, path, start_world_pos, end_world_pos):
    """
    Показывает 3D-сцену с моделью, проходимыми точками и, если есть, путем.
    ВСЕГДА показывает стартовую и конечную точки.
    """
    print("\n[Visualizer] Готовлю финальную 3D-визуализацию...")
    
    walkable_points = _get_walkable_points(grid)

    plotter = pv.Plotter(window_size=[1200, 800])
    
    plotter.add_mesh(original_mesh, style='surface', opacity=0.3, color='white')
    
    if walkable_points.shape[0] > 0:
        point_cloud = pv.PolyData(walkable_points)
        plotter.add_points(point_cloud, color='lime', point_size=3, render_points_as_spheres=True, opacity=0.5)

    if np.any(start_world_pos):
        plotter.add_mesh(pv.Sphere(radius=3, center=start_world_pos), color='blue')
        plotter.add_text("START", start_world_pos, color='white', font_size=10)
    
    if np.any(end_world_pos):
        plotter.add_mesh(pv.Sphere(radius=3, center=end_world_pos), color='red')
        plotter.add_text("END", end_world_pos, color='white', font_size=10)
    
    # --- ИСПРАВЛЕНИЕ ЗДЕСЬ ---
    if path:
        print("[Visualizer] Путь найден, отрисовываю его.")
        path_points = np.array(path)
        
        # 1. Создаем объект PolyData, который будет содержать нашу линию
        line = pv.PolyData()
        # 2. Задаем ему точки, через которые проходит линия
        line.points = path_points
        # 3. Говорим PyVista, как соединить эти точки:
        #    [кол-во точек, индекс_точки_0, индекс_точки_1, ...]
        num_points = len(path_points)
        connectivity = np.insert(np.arange(num_points), 0, num_points)
        line.lines = connectivity
        
        # 4. Добавляем на сцену наш готовый объект линии
        plotter.add_mesh(line, color='red', line_width=10) # Используем line_width
        
        plotter.add_text("3D Навигация: Путь найден!", position='upper_left', font_size=16, color='white')
    else:
        print("[Visualizer] Путь не найден или непроходим, показываю только точки.")
        plotter.add_text("3D Навигация: Путь НЕ найден", position='upper_left', font_size=16, color='white')
    
    print("[Visualizer] Показываю 3D-окно. Закройте его, чтобы завершить программу.")
    plotter.show()