import torch

x = torch.FloatTensor([1, 4])
y = torch.FloatTensor([2, 5])
z = torch.FloatTensor([3, 6])

print(torch.stack([x, y, z])) #default : 행을 기준으로 쌓음

print(torch.cat([x.unsqueeze(0), y.unsqueeze(0), z.unsqueeze(0)], dim=0)) #unsqueeze를 통해 2차원으로 형을 맞춰줌

print(torch.stack([x, y, z], dim=1)) #dim =1 : 열을 기준으로 스택


