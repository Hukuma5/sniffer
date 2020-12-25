result = [] 
stroka = '' 

with open(r'C:\Users\User\Downloads\pipec.txt', 'r') as inf: 
file = inf.readlines() 

for i in file: 
for j in range(len(i) - 2): 
if i[j] == '\\' and i[j + 1] == 'n': 
result.append(stroka) 
stroka = '' 
break 
stroka += i[j] 

with open(r'C:\Users\User\Downloads\pipec.txt', 'w') as ouf: 
for elem in result: 
ouf.write(elem + '\n')
