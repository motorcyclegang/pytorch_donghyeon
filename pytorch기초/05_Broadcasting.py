import torch
import numpy as np

m1 = torch.FloatTensor([[3, 3]])
m2 = torch.FloatTensor([[2, 2]])
print(m1 + m2) # 행렬합과 동일

# Vector + scalar
m1 = torch.FloatTensor([[1, 2]])
m2 = torch.FloatTensor([3]) # [3] -> [3, 3]
print(m1 + m2)

# 2 x 1 Vector + 1 x 2 Vector
m1 = torch.FloatTensor([[1, 2]])
'''
[1,2]
-> [[1,2],
    [1,2]]
'''
m2 = torch.FloatTensor([[3], [4]])
'''
[[3],[4]]
-> [[3,3],
    [4,4]]
'''
print(m1 + m2)

m1 = torch.FloatTensor([[1, 2], [3, 4]])
m2 = torch.FloatTensor([[1], [2]])
print('Shape of Matrix 1: ', m1.shape) # 2 x 2
print('Shape of Matrix 2: ', m2.shape) # 2 x 1
print(m1.matmul(m2)) # 2 x 1
'''
1 2 * 1 = 1*1+2*2 = 5
3 4   2   3*1+4*2   11
'''

m1 = torch.FloatTensor([[1, 2], [3, 4]])
m2 = torch.FloatTensor([[1], [2]])
print('Shape of Matrix 1: ', m1.shape) # 2 x 2
print('Shape of Matrix 2: ', m2.shape) # 2 x 1
print(m1 * m2) # 2 x 2
'''
element-wise
행렬의 크기를 동일하게 맞춘후 곱셈을 함
1 2 * 1 1 = 1*1 2*1 = 1 2
3 4   2 2   3*2 4*2   6 8
'''
print(m1.mul(m2))


t = torch.FloatTensor([1, 2])
print(t.mean())

t = torch.FloatTensor([[1, 2], [3, 4]])
print(t)

print(t.mean())

print(t.mean(dim=0)) #dim=0 : 첫번째 차원을 의미 즉 행을 의미
'''
# 실제 연산 과정
t.mean(dim=0)은 입력에서 첫번째 차원을 제거한다. 즉 열을 기준으로 보겠다

[[1., 2.],
 [3., 4.]]

1과 3의 평균을 구하고, 2와 4의 평균을 구한다.
결과 ==> [2., 3.]
'''

print(t.mean(dim=1)) #dim=1 두번째 차원 즉 열
'''
# 실제 연산 과정
t.mean(dim=1)은 입력에서 두번째 차원을 제거한다. 즉 행을 기준으로 보겠다

[[1., 2.],
 [3., 4.]]

1과 2의 평균을 구하고, 3와 4의 평균을 구한다.
결과 ==> [1.5, 3.5]
'''

print(t.mean(dim=-1)) #마지막 차원을 제거


t = torch.FloatTensor([[1, 2], [3, 4]])
print(t)

print(t.sum()) # 단순히 원소 전체의 덧셈을 수행
print(t.sum(dim=0)) # 행을 제거
print(t.sum(dim=1)) # 열을 제거
print(t.sum(dim=-1)) # 열을 제거

t = torch.FloatTensor([[1, 2], [3, 4]])
print(t)

print(t.max()) # Returns one value: max

print(t.max(dim=0)) # Returns two values: max and argmax
'''
# [1, 1]가 무슨 의미인지 봅시다. 기존 행렬을 다시 상기해봅시다.
[[1, 2],
 [3, 4]]
첫번째 열에서 0번 인덱스는 1, 1번 인덱스는 3입니다.
두번째 열에서 0번 인덱스는 2, 1번 인덱스는 4입니다.
다시 말해 3과 4의 인덱스는 [1, 1]입니다.
'''

print('Max: ', t.max(dim=0)[0])
print('Argmax: ', t.max(dim=0)[1]) #인덱스를 반환

print(t.max(dim=1))
print(t.max(dim=-1))



