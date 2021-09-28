'''
training dataset :  예측을 위해 사용하는 데이터 셋
test dataset : 이 모델이 얼마나 잘 작동하는지 판별하는 데이터 셋
'''

import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim

# 현재 실습하고 있는 파이썬 코드를 재실행해도 다음에도 같은 결과가 나오도록 랜덤 시드(random seed)를 줍니다.
torch.manual_seed(1)

x_train = torch.FloatTensor([[1], [2], [3]])
print(x_train)
print(x_train.shape)

y_train = torch.FloatTensor([[2], [4], [6]])
print(y_train)
print(y_train.shape)

# 가중치 W를 0으로 초기화하고 학습을 통해 값이 변경되는 변수임을 명시함.
W = torch.zeros(1, requires_grad=True) 
# 가중치 W를 출력
print(W) 

#편향 도 0으로 초기화하고, 학습을 통해 값이 변경되는 변수임을 명시함.
b = torch.zeros(1, requires_grad=True)
print(b)

# 현재 상태의 직선 방정식 y=0*x+0

#파이토치 코드 상의 가설 선언
hypothesis = x_train * W + b
print(hypothesis)

# 앞서 배운 torch.mean으로 평균을 구한다.
#선형회귀 비용함수에 해당되는 평균 제곱 오차 선언
cost = torch.mean((hypothesis - y_train) ** 2) 
print(cost)

'''
SGD : 경사하강법의 일종
lr : 학습률
학습대상인 W,b가  SGD의 입력이 됨
'''
optimizer = optim.SGD([W, b], lr=0.01)

nb_epochs = 1999 # 원하는만큼 경사 하강법을 반복
for epoch in range(nb_epochs + 1):

    # H(x) 계산
    hypothesis = x_train * W + b

    # cost 계산
    cost = torch.mean((hypothesis - y_train) ** 2)

    # cost로 H(x) 개선
    optimizer.zero_grad() # gradient를 0으로 초기화
    cost.backward() # 비용 함수를 미분하여 gradient 계산
    optimizer.step() # W와 b를 업데이트

    # 100번마다 로그 출력
    if epoch % 100 == 0:
        print('Epoch {:4d}/{} W: {:.3f}, b: {:.3f} Cost: {:.6f}'.format(
            epoch, nb_epochs, W.item(), b.item(), cost.item()
        ))