# pyvista_widget.py

import pyvista as pv
import numpy as np
from PyQt6.QtWidgets import QFrame, QVBoxLayout
from PyQt6.QtCore import pyqtSignal, Qt
from pyvistaqt import QtInteractor

class PyVistaWidget(QFrame):
    """
    Виджет, который встраивает 3D-сцену PyVista в окно PyQt.
    Теперь он умеет посылать сигнал, когда пользователь кликает по модели.
    """
    # Создаем сигнал, который будет передавать list (координаты точки)
    point_picked = pyqtSignal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.plotter = QtInteractor(self)
        layout.addWidget(self.plotter.interactor)
        
        self.plotter.add_axes()
        self.plotter.set_background('gray')

        self.plotter.interactor.setMouseTracking(True)

    def mousePressEvent(self, event):
        """
        Стандартный Qt-метод, который перехватывает клики мыши по этому виджету.
        """
        # Проверяем, что была нажата именно левая кнопка
        if event.button() == Qt.MouseButton.LeftButton:
            position = event.pos()
            # Используем встроенный метод плоттера для определения 3D-координаты
            picked_point, _ = self.plotter.pick_at(position)
            
            if picked_point is not None:
                print(f"[PyVistaWidget] Клик зарегистрирован в 3D-координате: {picked_point}")
                # ИСПУСКАЕМ СИГНАЛ, передавая в него координату
                self.point_picked.emit(list(picked_point))
        
        # Передаем событие дальше, чтобы стандартное управление (вращение и т.д.) работало
        super().mousePressEvent(event)

    def start_picking(self):
        """Активирует режим выбора точки на 3D-модели."""
        print("[PyVistaWidget] Режим выбора точки активирован.")
        # Создаем обработчик, который будет вызван при клике
        def callback(points):
            if points:
                point = points[0] # Берем первую точку из списка
                print(f"[PyVistaWidget] Клик зарегистрирован в 3D-координате: {point}")
                # ИСПУСКАЕМ СИГНАЛ, передавая в него координату
                self.point_picked.emit(list(point))

        # Включаем надежный режим выбора точки на поверхности
        self.plotter.enable_surface_picking(callback=callback, show_point=False, show_path=False)

    def show_mesh(self, mesh, **kwargs):
        """Отображает 3D-модель (меш) на сцене."""
        self.plotter.add_mesh(mesh, **kwargs)

    def add_points(self, points, **kwargs):
        """Добавляет точки на сцену."""
        # PyVista ожидает, что точки будут в виде объекта PolyData
        point_cloud = pv.PolyData(points)
        self.plotter.add_points(point_cloud, **kwargs)

    def add_path(self, path_points):
        """Добавляет линию пути на сцену."""
        if not path_points or len(path_points) == 0:
            return
            
        path_points_np = np.array(path_points)
        line = pv.PolyData()
        line.points = path_points_np
        connectivity = np.insert(np.arange(len(path_points_np)), 0, len(path_points_np))
        line.lines = connectivity
        self.plotter.add_mesh(line, color='red', line_width=10)
    
    def add_sphere(self, center, color, radius=3):
        """Добавляет сферу на сцену."""
        if center is not None and np.any(center):
            self.plotter.add_mesh(pv.Sphere(radius=radius, center=center), color=color)

    def clear(self):
        """Очищает сцену."""
        self.plotter.clear()
