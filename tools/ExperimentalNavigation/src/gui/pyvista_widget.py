# src/gui/pyvista_widget.py
from PyQt6.QtWidgets import QFrame, QVBoxLayout
from PyQt6.QtCore import pyqtSignal, Qt
from pyvistaqt import QtInteractor
import pyvista as pv
import numpy as np

class PyVistaWidget(QFrame):
    # Сигнал, который передает 3D-координату клика
    point_picked = pyqtSignal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.plotter = QtInteractor(self)
        layout.addWidget(self.plotter.interactor)
        
        self.plotter.add_axes()
        self.plotter.set_background('gray')

    def mousePressEvent(self, event):
        """
        Стандартный Qt-метод, который перехватывает клики мыши по этому виджету.
        """
        # Проверяем, что была нажата именно левая кнопка
        if event.button() == Qt.MouseButton.LeftButton:
            position_2d = event.pos()
            
            # Используем встроенный метод плоттера для определения 3D-координаты
            picker = self.plotter.renderer.picker
            picker.Pick(position_2d.x(), position_2d.y(), 0, self.plotter.renderer)
            picked_point = picker.GetPickPosition()
            
            # ИСПУСКАЕМ СИГНАЛ, передавая в него координату
            self.point_picked.emit(list(picked_point))
        
        # Передаем событие дальше, чтобы стандартное управление работало
        super().mousePressEvent(event)
    
    # --- Функции для добавления объектов на сцену (без изменений) ---
    def show_mesh(self, mesh, **kwargs): self.plotter.add_mesh(mesh, **kwargs)
    def add_points(self, points, **kwargs): self.plotter.add_points(points, **kwargs)
    def add_sphere(self, center, **kwargs): self.plotter.add_sphere(center, **kwargs)
    def remove_actor(self, name): self.plotter.remove_actor(name)
    def clear(self): self.plotter.clear()

    def add_mesh(self, mesh, **kwargs):
        """Прокси-метод для добавления меша на сцену."""
        self.plotter.add_mesh(mesh, **kwargs)

    def add_points(self, points, **kwargs):
        """Прокси-метод для добавления точек на сцену."""
        # PyVista ожидает, что точки будут в виде объекта PolyData
        point_cloud = pv.PolyData(points)
        self.plotter.add_points(point_cloud, **kwargs)

    def add_sphere(self, center, name=None, color='yellow', radius=3.0):
            """Создает и добавляет сферу на сцену."""
            if center is not None:
                sphere_mesh = pv.Sphere(radius=radius, center=center)
                self.plotter.add_mesh(sphere_mesh, name=name, color=color)

    def remove_actor(self, name):
        """Прокси-метод для удаления объекта со сцены."""
        self.plotter.remove_actor(name)

    def clear(self):
        """Прокси-метод для полной очистки сцены."""
        self.plotter.clear()

    def add_path(self, path_points, name=None):
        """Добавляет линию пути на сцену."""
        if not path_points or len(path_points) == 0:
            return
            
        path_points_np = np.array(path_points)
        line = pv.PolyData()
        line.points = path_points_np
        connectivity = np.insert(np.arange(len(path_points_np)), 0, len(path_points_np))
        line.lines = connectivity
        self.plotter.add_mesh(line, color='red', line_width=10, name=name)