import pandas as pd
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
import pickle


df=pd.read_csv('./dynamicTraningData.csv', sep=',')
df = df.loc[(df!=0).any(axis=1)]
df = df.fillna(0)
y = df['category']
X = df.drop(['category'],axis=1)
feature_list = list(X.columns)
print(X.shape)

# scaler = StandardScaler()
# scaler.fit(X)
# X = scaler.transform(X)
# pca= PCA(0.99)
# pca.fit(X)
# X = pca.transform(X)
# pickle.dump(pca, open("./dynamicOutput/pca.pkl","wb"))
# print(X.shape)

tree = DecisionTreeClassifier(max_depth = 2)
tree.fit(X,y)


model = RandomForestClassifier(n_estimators=100)
model.fit(X, y)

filename = './scriptedDynamicModel.sav'
filenameTree = './scriptedDynamicModelTree.sav'
pickle.dump(model, open(filename, 'wb'))
pickle.dump(model, open(filenameTree, 'wb'))


#Random Forest
#
# df2 = pd.read_csv("TestData.csv",sep=",")
# df2 = df2.loc[(df != 0).any(axis=1)]
# df2 = df2.drop(['name'],axis=1)
# df2 = df2.fillna(0)
# X_t = df2
# scaler2 = StandardScaler()
# scaler2.fit(X_t)
# X_t = scaler2.transform(X_t)
#
#
# pca_reload = pickle.load(open("pca.pkl",'rb'))
# X_t = pca_reload .transform(X_t)
#
# yhat = model.predict(X_t)
# yhat