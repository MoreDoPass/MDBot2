# src/core/pathfinder/pathfinder.py

import numpy as np
import heapq
import trimesh
from .. import agent_params

class Node3D:
    def __init__(self, position, parent=None):
        self.position = position; self.parent = parent
        self.g = 0; self.h = 0; self.f = 0
    def __eq__(self, other): return self.position == other.position
    def __lt__(self, other): return self.f < other.f
    def __hash__(self): return hash(self.position)

class Pathfinder:
    def __init__(self, nav_grid, transform):
        """
        Инициализирует поисковик пути.
        :param nav_grid: 3D-массив, где 2 - проходимый воксель.
        :param transform: Матрица трансформации из воксельных координат в мировые.
        """
        self.nav_grid = nav_grid
        self.transform = transform
        self.shape = nav_grid.shape
        self.movements = [(x, y, z) for x in [-1, 0, 1] for y in [-1, 0, 1] for z in [-1, 0, 1] if not (x == 0 and y == 0 and z == 0)]
        print(f"[Pathfinder] Инициализирован. Макс. высота шага: {agent_params.MAX_STEP_HEIGHT} игровых единиц.")

    def find_path(self, start_voxel, end_voxel, status_callback=None):
        print(f"[Pathfinder] Поиск 3D-пути от {start_voxel} до {end_voxel}...")
        
        start_node = Node3D(start_voxel)
        end_node = Node3D(end_voxel)

        open_heap = []; heapq.heappush(open_heap, (start_node.f, start_node))
        open_set = {start_node.position: start_node}
        closed_set = set()
        
        iterations = 0
        while open_heap:
            iterations += 1
            if status_callback and iterations % 2000 == 0:
                status_callback(f"Поиск... Проверено узлов: {iterations}")

            _, current_node = heapq.heappop(open_heap)
            
            if current_node.position == end_node.position:
                path = []; current = current_node
                while current is not None:
                    path.append(current.position); current = current.parent
                print(f"[Pathfinder] Путь найден! Итераций: {iterations}. Длина: {len(path)} шагов.")
                return path[::-1]

            closed_set.add(current_node.position)
            open_set.pop(current_node.position, None)

            for move in self.movements:
                node_position = tuple(np.array(current_node.position) + move)

                if not (0 <= node_position[0] < self.shape[0] and
                        0 <= node_position[1] < self.shape[1] and
                        0 <= node_position[2] < self.shape[2]):
                    continue
                
                if self.nav_grid[node_position] != 2: continue
                if node_position in closed_set: continue
                
                # --- ПРОВЕРКА ВЫСОТЫ ШАГА В МИРОВЫХ КООРДИНАТАХ ---
                current_world_pos = trimesh.transform_points([current_node.position], self.transform)[0]
                neighbor_world_pos = trimesh.transform_points([node_position], self.transform)[0]
                
                world_height_diff = abs(neighbor_world_pos[2] - current_world_pos[2])
                
                if world_height_diff > agent_params.MAX_STEP_HEIGHT:
                    continue # Слишком высокая ступенька, игнорируем этого соседа

                g_cost = current_node.g + np.linalg.norm(move)
                
                if node_position in open_set and g_cost >= open_set[node_position].g:
                    continue

                h_cost = np.linalg.norm(np.array(neighbor_world_pos) - np.array(voxel_to_world(end_voxel, self.transform)))
                
                neighbor_node = Node3D(node_position, current_node)
                neighbor_node.g = g_cost
                neighbor_node.h = h_cost
                neighbor_node.f = g_cost + h_cost
                
                heapq.heappush(open_heap, (neighbor_node.f, neighbor_node))
                open_set[node_position] = neighbor_node
                
        print(f"[Pathfinder] Путь не найден. Итераций: {iterations}")
        return None

def voxel_to_world(voxel_idx, transform): # Добавим хелпер сюда
    return trimesh.transform_points(np.array([voxel_idx]), transform)[0]