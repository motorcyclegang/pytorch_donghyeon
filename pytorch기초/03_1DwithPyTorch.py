import torch
import numpy as np

'''
Tensor : 일종의 행렬이라 이해하면 좋을 듯
'''

t = torch.FloatTensor([0., 1., 2., 3., 4., 5., 6.])
print(t)

print(t.dim())  # rank. 즉, 차원
print(t.shape)  # shape, tensor가 어떤 구조인지 확인(행, 열 등)
print(t.size()) # shape, shape와 동일한 결과 추출

print(t[0], t[1], t[-1])  # 인덱스로 접근
print(t[2:5], t[4:-1])    # 슬라이싱
print(t[:2], t[3:])       # 슬라이싱


