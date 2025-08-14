# src/gui/main_window.py
from PyQt6.QtWidgets import (QApplication, QMainWindow, QPushButton, QFileDialog, 
                             QWidget, QVBoxLayout, QHBoxLayout, QLabel, QGridLayout, QLineEdit, QTextEdit)
import trimesh
import numpy as np
from .pyvista_widget import PyVistaWidget 
from core.voxelizer.voxelizer import Voxelizer
from core.pathfinder.pathfinder import Pathfinder

def world_to_voxel(world_pos, transform):
    inverse_transform = np.linalg.inv(transform)
    voxel_coords = trimesh.transform_points(np.array([world_pos]), inverse_transform)[0]
    return tuple(np.round(voxel_coords).astype(int))

def voxel_to_world(voxel_idx, transform):
    return trimesh.transform_points(np.array([voxel_idx]), transform)[0]

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WoW Navigation Tool")
        self.setGeometry(100, 100, 1400, 900)

        self.mesh = None; self.voxelizer = None; self.pathfinder = None

        main_layout = QHBoxLayout()
        self.pv_widget = PyVistaWidget()
        main_layout.addWidget(self.pv_widget, 1)

        control_panel = QWidget(); control_panel.setFixedWidth(300)
        control_layout = QVBoxLayout(control_panel)
        main_layout.addWidget(control_panel)
        
        control_layout.addWidget(QLabel("<h3>1. Построение</h3>"))
        self.build_btn = QPushButton("Выбрать .obj и Построить Карту")
        self.build_btn.clicked.connect(self.build_navigation)
        control_layout.addWidget(self.build_btn)

        control_layout.addWidget(QLabel("<h3>2. Поиск Пути</h3>"))
        form_layout = QGridLayout()
        form_layout.addWidget(QLabel("<b>СТАРТ (X,Y,Z)</b>"), 0, 0)
        self.start_input = QLineEdit("10345.4, -6356.7, 33.0")
        form_layout.addWidget(self.start_input, 0, 1)
        form_layout.addWidget(QLabel("<b>ФИНИШ (X,Y,Z)</b>"), 1, 0)
        self.end_input = QLineEdit("10351.9, -6315.9, 29.9")
        form_layout.addWidget(self.end_input, 1, 1)
        control_layout.addLayout(form_layout)
        
        self.find_path_btn = QPushButton("Найти Путь")
        self.find_path_btn.clicked.connect(self.find_path)
        control_layout.addWidget(self.find_path_btn)

        control_layout.addWidget(QLabel("<h3>Найденный путь</h3>"))
        self.path_output = QTextEdit(); self.path_output.setReadOnly(True)
        control_layout.addWidget(self.path_output)

        control_layout.addStretch()
        self.status_label = QLabel("Ожидание..."); self.status_label.setWordWrap(True)
        control_layout.addWidget(self.status_label)

        self.central_widget = QWidget(); self.central_widget.setLayout(main_layout)
        self.setCentralWidget(self.central_widget)

    def build_navigation(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Выберите .obj", "", "OBJ Files (*.obj)")
        if not file_path: return

        self.mesh = trimesh.load(file_path, force='mesh')
        if not self.mesh or self.mesh.is_empty:
            self.status_label.setText("ОШИБКА: Меш не загружен."); return
            
        # --- Увеличиваем разрешение ---
        self.voxelizer = Voxelizer(self.mesh, resolution=512)
        self.voxelizer.build()
        
        # --- Передаем матрицу трансформации ---
        self.pathfinder = Pathfinder(
            self.voxelizer.walkable_mask,
            self.voxelizer.transform
        )
        
        self.pv_widget.clear()
        self.pv_widget.show_mesh(self.mesh, style='surface', opacity=0.1, color='white')
        walkable_coords = self.voxelizer.get_walkable_world_coords()
        if len(walkable_coords) > 0:
            self.pv_widget.add_points(walkable_coords, name="walkable", color='lime', point_size=3)
        self.status_label.setText("Карта построена. Вводите координаты.")

    def find_path(self):
        if not self.pathfinder:
            self.status_label.setText("Сначала постройте карту!"); return
        
        start_w, end_w, start_v_raw, end_v_raw = self._get_points()
        if start_w is None: return

        start_v = self._find_nearest_walkable(start_v_raw)
        end_v = self._find_nearest_walkable(end_v_raw)

        if not start_v or not end_v:
            self.status_label.setText("Не удалось найти проходимую точку старта/финиша рядом."); return
        
        path_voxels = self.pathfinder.find_path(start_v, end_v, self.status_label.setText)
        
        self.pv_widget.remove_actor("path")
        self.pv_widget.remove_actor("start_sphere")
        self.pv_widget.remove_actor("end_sphere")
        self.pv_widget.add_sphere(start_w, name="start_sphere", color='blue')
        self.pv_widget.add_sphere(end_w, name="end_sphere", color='red')

        if path_voxels:
            path_world = [voxel_to_world(v, self.voxelizer.transform) for v in path_voxels]
            self.pv_widget.add_path(path_world, name="path")
            
            path_text = "\n".join([f"({p[0]:.2f}, {p[1]:.2f}, {p[2]:.2f})" for p in path_world])
            self.path_output.setText(path_text)
            self.status_label.setText(f"Путь найден! {len(path_voxels)} шагов.")
        else:
            self.path_output.setText("")
            self.status_label.setText("Путь не найден.")

    def _get_points(self):
        try:
            start_w = np.array([float(x.strip()) for x in self.start_input.text().split(',')])
            end_w = np.array([float(x.strip()) for x in self.end_input.text().split(',')])
            start_v = world_to_voxel(start_w, self.voxelizer.transform)
            end_v = world_to_voxel(end_w, self.voxelizer.transform)
            return start_w, end_w, start_v, end_v
        except Exception as e:
            self.status_label.setText(f"Ошибка координат: {e}"); return None, None, None, None

    def _find_nearest_walkable(self, start_voxel):
        grid = self.voxelizer.walkable_mask.astype(np.uint8) * 2
        if grid[start_voxel] == 2: return start_voxel
        max_radius = 15
        for radius in range(1, max_radius):
            for x in range(-radius, radius+1):
                for y in range(-radius, radius+1):
                    for z in range(-radius, radius+1):
                        if abs(x)!=radius and abs(y)!=radius and abs(z)!=radius: continue
                        check_pos = (start_voxel[0]+x, start_voxel[1]+y, start_voxel[2]+z)
                        if not (0<=check_pos[0]<grid.shape[0] and 0<=check_pos[1]<grid.shape[1] and 0<=check_pos[2]<grid.shape[2]): continue
                        if grid[check_pos] == 2:
                            print(f"[Snap] Точка {start_voxel} привязана к {check_pos}"); return check_pos
        print(f"[Snap] Не найдено проходимых точек рядом с {start_voxel}"); return None