import torch

x = torch.FloatTensor([[0, 1, 2], [2, 1, 0]])
print(x)

print(torch.ones_like(x)) # 입력 텐서와 크기를 동일하게 하면서 값을 1로 채우기

print(torch.zeros_like(x)) # 입력 텐서와 크기를 동일하게 하면서 값을 0으로 채우기

x = torch.FloatTensor([[1, 2], [3, 4]])

print(x.mul(2.)) # 곱하기 2를 수행한 결과를 출력
print(x) # 기존의 값 출력

print(x.mul_(2.))  #연산뒤에 _를 붙일 경우 :  곱하기 2를 수행한 결과를 변수 x에 값을 저장하면서 결과를 출력
print(x) # 기존의 값 출력