import torch

ft = torch.FloatTensor([[0], [1], [2]])
print(ft)
print(ft.shape)

print(ft.squeeze()) # 크기가 1인 차원을 없앰
print(ft.squeeze().shape)