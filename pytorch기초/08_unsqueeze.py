import torch

ft = torch.Tensor([0, 1, 2])
print(ft.shape)

print(ft.unsqueeze(0)) # 인덱스가 0부터 시작하므로 0은 첫번째 차원을 의미한다.
print(ft.unsqueeze(0).shape)

print(ft.view(1, -1))
print(ft.view(1, -1).shape)

print(ft.unsqueeze(1))
print(ft.unsqueeze(1).shape)

print(ft.unsqueeze(-1))
print(ft.unsqueeze(-1).shape)