import torch

x = torch.FloatTensor([[1, 2], [3, 4]])
y = torch.FloatTensor([[5, 6], [7, 8]])

print(torch.cat([x, y], dim=0)) #dim=0 행을 늘려라

print(torch.cat([x, y], dim=1)) #dim=1 열을 늘려라