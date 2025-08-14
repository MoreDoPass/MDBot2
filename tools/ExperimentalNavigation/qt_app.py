# qt_app.py

import sys, trimesh, numpy as np
from PyQt6.QtWidgets import *
import voxelizer, pathfinder_3d
from pyvista_widget import PyVistaWidget

def world_to_voxel(world_pos, vi):
    """Преобразует мировые 3D-координаты в (x,y,z) индекс вокселя."""
    # Применяем обратную матрицу трансформации
    inverse_transform = np.linalg.inv(vi['transform'])
    voxel_coords = trimesh.transform_points(np.array([world_pos]), inverse_transform)[0]
    # Округляем до ближайшего индекса
    return tuple(np.round(voxel_coords).astype(int))

def voxel_to_world(voxel_idx, vi):
    """Преобразует (x,y,z) индекс вокселя в мировые 3D-координаты."""
    # Применяем прямую матрицу трансформации
    return trimesh.transform_points(np.array([voxel_idx]), vi['transform'])[0]

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WoW Voxel Navigation [Диагностика]")
        self.setGeometry(100, 100, 1600, 900) # Сделаем окно шире
        self.mesh, self.voxel_info = None, None

        main_layout = QHBoxLayout()
        self.pv_widget = PyVistaWidget()
        main_layout.addWidget(self.pv_widget, 1)

        control_panel = QFrame(); control_panel.setFixedWidth(450) # Панель тоже шире
        control_layout = QVBoxLayout(control_panel)
        main_layout.addWidget(control_panel)
        
        control_layout.addWidget(QLabel("<h3>1. Инициализация</h3>"))
        self.load_btn = QPushButton("Загрузить и Вокселизировать")
        self.load_btn.clicked.connect(self.load_and_voxelize)
        control_layout.addWidget(self.load_btn)

        control_layout.addWidget(QLabel("<h3>2. Диагностика</h3>"))
        diag_layout = QHBoxLayout()
        self.check_voxels_btn = QPushButton("Проверить Воксели")
        self.check_voxels_btn.clicked.connect(self.check_voxels)
        diag_layout.addWidget(self.check_voxels_btn)
        control_layout.addLayout(diag_layout)

        control_layout.addWidget(QLabel("<h3>3. Поиск Пути</h3>"))
        form_layout = QGridLayout()
        form_layout.addWidget(QLabel("<b>СТАРТ (X,Y,Z)</b>"), 0, 0)
        self.start_input = QLineEdit("10599.4, -5844.7, 10.1")
        form_layout.addWidget(self.start_input, 0, 1)
        form_layout.addWidget(QLabel("<b>ФИНИШ (X,Y,Z)</b>"), 1, 0)
        self.end_input = QLineEdit("10620.5, -5815.2, 11.2")
        form_layout.addWidget(self.end_input, 1, 1)
        control_layout.addLayout(form_layout)

        self.find_path_btn = QPushButton("Найти Путь")
        self.find_path_btn.clicked.connect(self.find_path)
        control_layout.addWidget(self.find_path_btn)

        # --- НОВЫЙ БЛОК: ВЫВОД ПУТИ ---
        control_layout.addWidget(QLabel("<h3>Найденный путь (мировые координаты)</h3>"))
        self.path_output = QTextEdit()
        self.path_output.setReadOnly(True)
        control_layout.addWidget(self.path_output)

        control_layout.addStretch()
        self.status_label = QLabel("Ожидание..."); self.status_label.setWordWrap(True)
        control_layout.addWidget(self.status_label)
        
        self.central_widget = QWidget(); self.central_widget.setLayout(main_layout)
        self.setCentralWidget(self.central_widget)
    
    def _find_nearest_walkable(self, start_voxel):
        """Ищет ближайший проходимый воксель (==1) от заданной точки."""
        grid = self.voxel_info['grid']
        if grid[start_voxel] == 2:
            return start_voxel # Точка уже проходима

        max_radius = 10 # Ограничение поиска, чтобы не зависнуть
        for radius in range(1, max_radius):
            for x in range(-radius, radius + 1):
                for y in range(-radius, radius + 1):
                    for z in range(-radius, radius + 1):
                        # Проверяем только "оболочку" куба, чтобы не делать лишних проверок
                        if abs(x) != radius and abs(y) != radius and abs(z) != radius:
                            continue
                        
                        check_pos = (start_voxel[0] + x, start_voxel[1] + y, start_voxel[2] + z)
                        
                        if not (0 <= check_pos[0] < grid.shape[0] and
                                0 <= check_pos[1] < grid.shape[1] and
                                0 <= check_pos[2] < grid.shape[2]):
                            continue
                        
                        if grid[check_pos] == 2:
                            print(f"[Snap] Точка {start_voxel} привязана к {check_pos}")
                            return check_pos
        return None # Не нашли проходимую точку рядом

    def load_and_voxelize(self):
        self.status_label.setText("Загрузка..."); QApplication.processEvents()
        self.mesh = trimesh.load("43_12_wow.obj", force='mesh')
        self.status_label.setText("Вокселизация..."); QApplication.processEvents()
        self.voxel_info = voxelizer.voxelize_mesh_advanced(self.mesh, resolution=256)
        self.status_label.setText("Готово. Проверьте воксели или ищите путь.")
        self.pv_widget.clear(); self.pv_widget.show_mesh(self.mesh, style='surface', opacity=0.1, color='white')

    def check_voxels(self):
        if not self.voxel_info: return
        start_w, end_w, start_v, end_v = self._get_points()
        if start_w is None: return

        # Привязываем точки к проходимым зонам
        snapped_start_v = self._find_nearest_walkable(start_v)
        snapped_end_v = self._find_nearest_walkable(end_v)

        self.pv_widget.clear(); self.pv_widget.show_mesh(self.mesh, opacity=0.1)
        self.pv_widget.add_sphere(start_w, 'magenta', radius=1) # Оригинальная точка
        self.pv_widget.add_sphere(end_w, 'magenta', radius=1)

        if snapped_start_v:
            self.pv_widget.add_sphere(voxel_to_world(snapped_start_v, self.voxel_info), 'cyan')
        if snapped_end_v:
            self.pv_widget.add_sphere(voxel_to_world(snapped_end_v, self.voxel_info), 'cyan')
            
        self.status_label.setText(
            f"Старт {start_v} -> {snapped_start_v if snapped_start_v else 'НЕТ РЯДОМ'}\n"
            f"Финиш {end_v} -> {snapped_end_v if snapped_end_v else 'НЕТ РЯДОМ'}\n"
            "Пурпурный = ваш ввод, Голубой = реальная точка старта/финиша."
        )


    def find_path(self):
        if not self.voxel_info: return
        start_w, end_w, start_v, end_v = self._get_points()
        if start_w is None: return

        # --- КЛЮЧЕВОЕ ИЗМЕНЕНИЕ ---
        navigable_start_v = self._find_nearest_walkable(start_v)
        navigable_end_v = self._find_nearest_walkable(end_v)
        
        if not navigable_start_v or not navigable_end_v:
            self.status_label.setText("Не удалось найти проходимую точку старта/финиша рядом."); return

        path_voxels, closed_set = pathfinder_3d.astar_pathfind_3d(
            self.voxel_info['grid'], navigable_start_v, navigable_end_v, self.status_label.setText
        )
        
        self.pv_widget.clear(); self.pv_widget.show_mesh(self.mesh, opacity=0.1)
        self.pv_widget.add_sphere(start_w, 'blue'); self.pv_widget.add_sphere(end_w, 'red')

        if path_voxels:
            # --- ИЗМЕНЕНИЯ ЗДЕСЬ ---
            # 1. Трансформируем путь в мировые координаты с помощью ПРАВИЛЬНОЙ функции
            path_world = [voxel_to_world(v, self.voxel_info) for v in path_voxels]
            
            # 2. Рисуем путь, который теперь будет на правильной высоте
            self.pv_widget.add_path(path_world)
            
            # 3. Форматируем и выводим координаты пути в текстовое поле
            path_text = "\n".join([f"({p[0]:.2f}, {p[1]:.2f}, {p[2]:.2f})" for p in path_world])
            self.path_output.setText(path_text)
            
            self.status_label.setText(f"Путь найден! {len(path_voxels)} шагов.")
        else:
            self.path_output.setText("") # Очищаем поле, если пути нет
            self.status_label.setText("Путь не найден.")

    def _get_points(self):
        try:
            start_w = np.array([float(x.strip()) for x in self.start_input.text().split(',')])
            end_w = np.array([float(x.strip()) for x in self.end_input.text().split(',')])
            start_v = world_to_voxel(start_w, self.voxel_info)
            end_v = world_to_voxel(end_w, self.voxel_info)
            return start_w, end_w, start_v, end_v
        except Exception as e:
            self.status_label.setText(f"Ошибка в формате координат: {e}"); return None, None, None, None

if __name__ == "__main__":
    app = QApplication(sys.argv); window = MainWindow(); window.show(); sys.exit(app.exec())