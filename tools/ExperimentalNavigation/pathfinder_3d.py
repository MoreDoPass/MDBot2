# pathfinder_3d.py

import numpy as np
import heapq

class Node3D:
    def __init__(self, position, parent=None):
        self.position = position; self.parent = parent
        self.g = 0; self.h = 0; self.f = 0
    def __eq__(self, other): return self.position == other.position
    def __lt__(self, other): return self.f < other.f
    def __hash__(self): return hash(self.position) # Необходимо для set

def astar_pathfind_3d(voxel_grid, start_coords, end_coords, status_callback=None):
    print(f"\n[Pathfinder3D] Начинаю поиск 3D-пути от {start_coords} до {end_coords}...")
    
    start_node = Node3D(start_coords)
    end_node = Node3D(end_coords)

    open_heap = []; heapq.heappush(open_heap, (start_node.f, start_node))
    open_set = {start_node.position: start_node} # Используем set для быстрого доступа
    closed_set = set()
    
    movements = [(x, y, z) for x in [-1, 0, 1] for y in [-1, 0, 1] for z in [-1, 0, 1] if not (x == 0 and y == 0 and z == 0)]
    
    iterations = 0
    while open_heap:
        iterations += 1
        if status_callback and iterations % 500 == 0:
            status_callback(f"Поиск... Проверено узлов: {iterations}")

        _, current_node = heapq.heappop(open_heap)
        
        if current_node.position == end_node.position:
            path = []; current = current_node
            while current is not None:
                path.append(current.position); current = current.parent
            print(f"[Pathfinder3D] Путь найден! Итераций: {iterations}. Длина: {len(path)} шагов.")
            return path[::-1], closed_set

        closed_set.add(current_node.position)
        open_set.pop(current_node.position, None)

        for move in movements:
            node_position = tuple(np.array(current_node.position) + move)

            if not (0 <= node_position[0] < voxel_grid.shape[0] and
                    0 <= node_position[1] < voxel_grid.shape[1] and
                    0 <= node_position[2] < voxel_grid.shape[2]):
                continue
            if voxel_grid[node_position] != 2: continue
            if node_position in closed_set: continue

            g_cost = current_node.g + np.linalg.norm(move)
            
            # --- КЛЮЧЕВОЕ ИСПРАВЛЕНИЕ ---
            # Если мы нашли лучший путь к узлу, который уже в очереди,
            # мы не добавляем новый, а обновляем старый.
            if node_position in open_set:
                if g_cost >= open_set[node_position].g:
                    continue # Старый путь лучше или такой же, ничего не делаем
            # --------------------------------

            h_cost = np.linalg.norm(np.array(node_position) - np.array(end_node.position))
            
            neighbor_node = Node3D(node_position, current_node)
            neighbor_node.g = g_cost
            neighbor_node.h = h_cost
            neighbor_node.f = g_cost + h_cost
            
            heapq.heappush(open_heap, (neighbor_node.f, neighbor_node))
            open_set[node_position] = neighbor_node
            
    print(f"[Pathfinder3D] Путь не найден. Итераций: {iterations}")
    return None, closed_set