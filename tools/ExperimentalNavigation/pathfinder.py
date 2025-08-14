# pathfinder.py

import numpy as np

class Node:
    """Узел для алгоритма A*. Хранит свои координаты, стоимость и родителя."""
    def __init__(self, parent=None, position=None):
        self.parent = parent
        self.position = position # Координаты в сетке (x, y)

        self.g = 0 # Стоимость пути от старта до текущего узла
        self.h = 0 # Эвристическая стоимость от текущего узла до конца
        self.f = 0 # Общая стоимость (g + h)

    def __eq__(self, other):
        return self.position == other.position

def astar_pathfind(grid, start_coords, end_coords):
    """
    Находит путь от start_coords до end_coords на grid с помощью A*.
    Возвращает список 3D-координат пути.
    """
    print(f"\n[Pathfinder] Начинаю поиск пути от {start_coords} до {end_coords}...")

    # Создаем стартовый и конечный узлы
    start_node = Node(None, start_coords)
    end_node = Node(None, end_coords)

    # Инициализируем списки для открытых (еще не проверенных) и закрытых (уже проверенных) узлов
    open_list = []
    closed_list = []

    open_list.append(start_node)

    # Цикл, пока есть что проверять
    while len(open_list) > 0:
        # Находим узел с наименьшей стоимостью F в открытом списке
        current_node = open_list[0]
        current_index = 0
        for index, item in enumerate(open_list):
            if item.f < current_node.f:
                current_node = item
                current_index = index

        # Перемещаем его из открытого списка в закрытый
        open_list.pop(current_index)
        closed_list.append(current_node)

        # Если нашли цель - реконструируем путь
        if current_node == end_node:
            path = []
            current = current_node
            while current is not None:
                # Извлекаем мировые координаты из сетки по координатам узла
                world_pos = grid[current.position[0], current.position[1], 1:4]
                path.append(world_pos)
                current = current.parent
            print(f"[Pathfinder] Путь найден! Длина: {len(path)} шагов.")
            return path[::-1] # Возвращаем перевернутый путь (от старта к финишу)

        # Генерируем дочерние узлы (соседей)
        children = []
        for new_position in [(0, -1), (0, 1), (-1, 0), (1, 0), (-1, -1), (-1, 1), (1, -1), (1, 1)]: # 8 направлений
            node_position = (current_node.position[0] + new_position[0], current_node.position[1] + new_position[1])

            # Проверяем, что не вышли за границы сетки
            if node_position[0] > (grid.shape[0] - 1) or node_position[0] < 0 or \
               node_position[1] > (grid.shape[1] - 1) or node_position[1] < 0:
                continue

            # Проверяем, что ячейка проходима
            if grid[node_position[0], node_position[1], 0] != 1.0:
                continue

            new_node = Node(current_node, node_position)
            children.append(new_node)

        # Обрабатываем дочерние узлы
        for child in children:
            # Если узел уже в закрытом списке - пропускаем
            if child in closed_list:
                continue
            
            # Считаем стоимости
            child.g = current_node.g + 1
            # Эвристика - простое расстояние до цели (Манхэттенское расстояние)
            child.h = ((child.position[0] - end_node.position[0]) ** 2) + ((child.position[1] - end_node.position[1]) ** 2)
            child.f = child.g + child.h

            # Если узел уже в открытом списке и новый путь до него хуже - пропускаем
            if len([open_node for open_node in open_list if child == open_node and child.g > open_node.g]) > 0:
                continue

            open_list.append(child)
            
    print("[Pathfinder] Путь не найден.")
    return None