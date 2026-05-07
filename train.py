import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib

# 1. Загрузка данных
print("🚀 Загрузка данных...")
df = pd.read_csv('Train_data.csv')

# 2. Предобработка
# Оставляем только числовые признаки для стабильности прототипа
X = df.select_dtypes(include=[np.number])
y = df['class']

# 3. Разделение на выборки
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 4. Обучение модели
print("🧠 Обучение модели Random Forest (100 деревьев)...")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# 5. Оценка (для твоего отчета)
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"✅ Модель обучена! Точность (Accuracy): {acc:.4f}")
print("\nОтчет по классификации:")
print(classification_report(y_test, y_pred))

# 6. Сохранение артефактов
joblib.dump(model, 'ids_model.pkl')
joblib.dump(X.columns.tolist(), 'features.pkl') 
print("💾 Все файлы сохранены: ids_model.pkl, features.pkl")