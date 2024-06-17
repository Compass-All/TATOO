import matplotlib.pyplot as plt
from brokenaxes import brokenaxes
import numpy as np
import matplotlib
#matplotlib.rcParams['font.family'] = 'Times New Roman'
#matplotlib.rcParams['font.weight'] = 'bold'
# 数据
programs = ['readelf', 'size', 'objdump', 'tiffinfo', 'tiff2bw', 'nasm', 'bison']
AFL = [1.158094578, 1.014067085, 1.069111719, 1.016168538, 1.055523031, 3.20935852, 3.240647455]
PHMon = [1.178676596, 1.144574339, 1.128581216, 1.076548895, 1.097075573, 1.069176923, 1.05206892]
TATOO = [1.123452514, 1.074066411, 1.102833023, 1.075460381, 1.096141329, 1.073419055, 1.04726249]

x = np.arange(len(programs))  # 标签位置
width = 0.25  # 条形图的宽度
plt.figure(figsize=(8, 4))
# 创建断裂轴图表

bax = brokenaxes(ylims=((1, 1.2), (3.2, 3.25)), hspace=.1)

# 绘制条形图
print(x-width)
rects1 = bax.bar(x - width, AFL, width, label='AFL', color='black', alpha=0.3)
rects2 = bax.bar(x, PHMon, width, label='PHMon', color='black', alpha=0.7)
rects3 = bax.bar(x + width, TATOO, width, label='TATOO', color='black', hatch='-')

bax.set_xticks(x)


programs1 = ['','readelf', 'size', 'objdump', 'tiffinfo', 'tiff2bw', 'nasm', 'bison']
bax.set_xticklabels(programs1, fontsize=13)
#bax.set_title('Scores by program and method')
bax.legend(loc='upper left')
bax.set_ylabel('Overall Performance Overhead', fontsize=13)
# 在条形图上添加数值标签
def autolabel(values, x_positions, width, bax):
    for value, x_pos in zip(values, x_positions):
        for s in bax.axs:
            s.annotate('{}'.format(round(value, 2)),
                       xy=(x_pos, value),
                       xytext=(0, 3),  # 3点垂直偏移
                       textcoords="offset points",
                       ha='center', va='bottom', fontsize=7)

# 为每个子轴添加标签
x_positions = x - width  # AFL 的 x 位置
autolabel(AFL, x_positions, width, bax)

x_positions = x  # PHMon 的 x 位置
autolabel(PHMon, x_positions, width, bax)

x_positions = x + width  # TATOO 的 x 位置
autolabel(TATOO, x_positions, width, bax)

plt.show()
