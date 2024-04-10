import json
with open('noinstru.json') as fp:
    #该方法传入一个文件对象
    dict1 = json.load(fp)
with open('instru.json') as fp:
    #该方法传入一个文件对象
    dict2 = json.load(fp)
    
diff = dict1.keys() & dict2
subname = dict1.keys() - dict2.keys()


diff_vals = [(k) for k in diff if dict1[k] != dict2[k]]
differ = [(k) for k in diff if dict1[k] == dict2[k]]
print(differ)
with open('dict.json','w') as fp:
    json.dump(diff_vals,fp)
with open('lib.json','w') as fp:
    json.dump(differ,fp)
print(subname)