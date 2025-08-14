# src/core/voxelizer.py
import trimesh
import numpy as np
from scipy.ndimage import binary_fill_holes
from .. import agent_params

class Voxelizer:
    def __init__(self, mesh, resolution=256):
        self.mesh = mesh
        self.resolution = resolution
        self.pitch = np.max(self.mesh.extents) / self.resolution
        self.transform = trimesh.transformations.scale_and_translate(scale=self.pitch, translate=self.mesh.bounds[0])
        
        self.solid_mask = None
        self.walkable_mask = None

        self.slope_fail_mask = None
        self.height_fail_mask = None
        print(f"[Voxelizer] Инициализирован. Размер вокселя: {self.pitch:.3f} игровых единиц.")

    def build(self):
        print("[Voxelizer] Начало сборки воксельной навигации...")
        self._create_solid_voxel_mask()
        self._create_walkable_voxel_mask()
        print("[Voxelizer] Сборка завершена.")

    def _create_solid_voxel_mask(self):
        print("  - Шаг 1: Вокселизация 'кожи' модели...")
        voxel_surface = self.mesh.voxelized(pitch=self.pitch)
        
        print("  - Шаг 2: Заполнение замкнутых пространств (деревья, скалы)...")
        # Используем scipy, чтобы "залить" все замкнутые объемы.
        # Это автоматически отсеет внутренности деревьев и т.д.
        self.solid_mask = binary_fill_holes(voxel_surface.matrix)
        print(f"  - Размер воксельной сетки: {self.solid_mask.shape}")

    def _create_walkable_voxel_mask(self):
        if self.solid_mask is None: raise ValueError("Сначала нужно создать маску твердых вокселей.")
        
        print("  - Шаг 3: Поиск проходимых поверхностей...")
        self.walkable_mask = np.zeros_like(self.solid_mask, dtype=bool)

        # Находим все воксели "пола" - те, что являются SOLID, но над ними AIR
        floor_indices = np.argwhere((self.solid_mask) & (~np.roll(self.solid_mask, -1, axis=2)))

        if len(floor_indices) == 0:
            print("  - ВНИМАНИЕ: Не найдено ни одной поверхности пола."); return

        print(f"    - Найдено {len(floor_indices)} потенциальных точек пола.")
        
        # --- Проверка параметров агента ---
        # 1. Проверка уклона
        floor_world_coords = trimesh.transform_points(floor_indices, self.transform)
        _, _, face_indices = trimesh.proximity.closest_point(self.mesh, floor_world_coords)
        normals = self.mesh.face_normals[face_indices]
        
        min_dot_product = np.cos(np.radians(agent_params.MAX_SLOPE_DEGREES))
        is_flat_enough = np.abs(np.dot(normals, [0, 0, 1])) > min_dot_product
        
        self.slope_fail_mask = np.zeros_like(self.solid_mask, dtype=bool)
        failed_slope_indices = tuple(floor_indices[~is_flat_enough].T)
        self.slope_fail_mask[failed_slope_indices] = True

        # 2. Проверка высоты агента (чтобы не бился головой)
        agent_height_in_voxels = int(np.ceil(agent_params.AGENT_HEIGHT / self.pitch))
        head_clearance_mask = np.ones(len(floor_indices), dtype=bool)
        
        for i in range(1, agent_height_in_voxels + 2): # +2 для запаса
             head_check_indices = floor_indices + [0, 0, i]
             valid_indices_mask = (head_check_indices[:, 2] < self.solid_mask.shape[2])
             valid_indices = head_check_indices[valid_indices_mask]
             
             # Если над головой есть SOLID воксель, то это место непроходимо
             head_clearance_mask[valid_indices_mask] &= ~self.solid_mask[tuple(valid_indices.T)]
        
        self.height_fail_mask = np.zeros_like(self.solid_mask, dtype=bool)
        failed_height_indices = tuple(floor_indices[~head_clearance_mask].T)
        self.height_fail_mask[failed_height_indices] = True
        # TODO: Проверка радиуса агента (самый сложный шаг, пока пропустим для скорости)

        # Финальная маска проходимости
        final_walkable_mask = is_flat_enough & head_clearance_mask
        # --- ИЗМЕНЕНИЕ: Проходимыми являются сами воксели ПОЛА, а не воздух над ними ---
        walkable_floor_indices = floor_indices[final_walkable_mask]
        
        # Создаем временную пустую маску и помечаем в ней проходимые точки значением 2
        temp_nav_grid = np.zeros_like(self.solid_mask, dtype=np.uint8)
        temp_nav_grid[tuple(walkable_floor_indices.T)] = 2
        
        # Теперь self.walkable_mask - это финальная карта, где 2 = проходимо
        self.walkable_mask = temp_nav_grid
        print(f"  - Найдено {len(walkable_floor_indices)} проходимых вокселей после всех проверок.")

    def get_voxel_info_at_world_coords(self, world_coords):
        """Возвращает полный диагностический отчет для точки в мире."""
        # Преобразуем мировые координаты в индекс вокселя
        voxel_idx = tuple(np.round(trimesh.transform_points(np.array([world_coords]), self.inverse_transform)[0]).astype(int))
        
        # Проверяем, чтобы индекс был в пределах сетки
        if not all(0 <= i < s for i, s in zip(voxel_idx, self.solid_mask.shape)):
            return "Точка вне воксельной сетки."

        report = f"Отчет для вокселя {voxel_idx}:\n"
        
        if self.walkable_mask[voxel_idx]:
            report += "СТАТУС: ПРОХОДИМЫЙ (WALKABLE)\n"
            return report

        # Если не проходимый, выясняем почему
        report += "СТАТУС: НЕПРОХОДИМЫЙ\n"
        if self.solid_mask[voxel_idx]:
            report += "  - Причина: Твердый объект (SOLID)\n"
        else:
            report += "  - Причина: Воздух, но не подходит для ходьбы (AIR)\n"

        # Ищем пол под этим вокселем
        floor_voxel_idx = (voxel_idx[0], voxel_idx[1], voxel_idx[2] - 1)
        if self.slope_fail_mask[floor_voxel_idx]:
            report += "    - Провал проверки: Слишком крутой уклон.\n"
        if self.height_fail_mask[floor_voxel_idx]:
            report += "    - Провал проверки: Недостаточно места над головой.\n"
        
        return report

    def get_debug_voxels(self):
        """Возвращает координаты и типы всех 'проблемных' вокселей для визуализации."""
        if self.walkable_mask is None: return {}
        
        # Возвращаем мировые координаты для каждого типа ошибки
        return {
            "walkable": self.get_walkable_world_coords(),
            "slope_fail": trimesh.transform_points(np.argwhere(self.slope_fail_mask), self.transform),
            "height_fail": trimesh.transform_points(np.argwhere(self.height_fail_mask), self.transform)
        }


    def get_walkable_world_coords(self):
            """Возвращает мировые координаты всех проходимых вокселей."""
            if self.walkable_mask is None: return np.array([])
            
            # --- ИЗМЕНЕНИЕ: Ищем воксели со значением 2 ---
            walkable_indices = np.argwhere(self.walkable_mask == 2)
            return trimesh.transform_points(walkable_indices, self.transform)