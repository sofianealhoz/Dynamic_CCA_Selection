import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import shap
import matplotlib.pyplot as plt
import numpy as np 
from sklearn.model_selection import StratifiedKFold

df = pd.read_csv('new_data.csv')

label_encoder = LabelEncoder()
df['label_encoded'] = label_encoder.fit_transform(df['label'])

print("Mapping labels:")
for i, label in enumerate(label_encoder.classes_):
    print(f"{i}: {label}")

# Validation par connexions
unique_connections = df['connection_id'].unique()
np.random.seed(42)
np.random.shuffle(unique_connections)
split_idx = int(len(unique_connections) * 0.8)
train_connections = unique_connections[:split_idx]
test_connections = unique_connections[split_idx:]
train_mask = df['connection_id'].isin(train_connections)
test_mask = df['connection_id'].isin(test_connections)

print(f"\nConnexions train: {len(train_connections)}")
print(f"Connexions test: {len(test_connections)}")

# Redéfinir X en enlevant connection_id
X = df.drop(['label', 'label_encoded', 'connection_id'], axis=1)
y_encoded = df['label_encoded']
y_original = df['label']

print(f"Features utilisées: {X.columns.tolist()}")

# Split par connexions
X_train = X[train_mask]
X_test = X[test_mask]
y_train_enc = y_encoded[train_mask]
y_test_enc = y_encoded[test_mask]
y_train_orig = y_original[train_mask]
y_test_orig = y_original[test_mask]

print(f"Train: {len(X_train)} échantillons")
print(f"Test: {len(X_test)} échantillons")
print(f"Distribution train: {y_train_orig.value_counts().to_dict()}")
print(f"Distribution test: {y_test_orig.value_counts().to_dict()}")

# Normalisation pour SVM et MLP
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Modèles
models = {
    'RandomForest': RandomForestClassifier(n_estimators=100, random_state=42),
    'XGBoost': XGBClassifier(random_state=42, eval_metric='logloss'),
    'SVM': SVC(kernel='rbf', random_state=42),
    'MLP': MLPClassifier(hidden_layer_sizes=(100, 50), random_state=42)
}

results = {}

for name, model in models.items():
    print(f"\n=== {name} ===")

    # Choisir les bonnes données selon le modèle
    if name in ['SVM', 'MLP']:
        X_train_model = X_train_scaled
        X_test_model = X_test_scaled
    else:
        X_train_model = X_train
        X_test_model = X_test

    if name == 'XGBoost':
        y_train_model = y_train_enc
        y_test_model = y_test_enc
    else:
        y_train_model = y_train_orig
        y_test_model = y_test_orig

    # Entraînement et prédiction
    model.fit(X_train_model, y_train_model)
    y_pred = model.predict(X_test_model)
    
    # Calcul accuracy
    accuracy = model.score(X_test_model, y_test_model)
    
    results[name] = {
        'model': model,
        'accuracy': accuracy,
        'predictions': y_pred
    }

    print(f"Accuracy: {accuracy:.4f}")
    print(f"Classification Report:")

    # Pour XGBoost, décoder les prédictions pour l'affichage
    if name == 'XGBoost':
        y_test_display = label_encoder.inverse_transform(y_test_model)
        y_pred_display = label_encoder.inverse_transform(y_pred)
        print(classification_report(y_test_display, y_pred_display))
    else:
        print(classification_report(y_test_model, y_pred))

print("\n=== COMPARAISON DES MODÈLES ===")
for name, result in results.items():
    print(f"{name}: {result['accuracy']:.4f}")

# Analyse SHAP sur RandomForest
best_model = results['RandomForest']['model']

print("\n=== ANALYSE SHAP EN COURS ===")

# Créer l'explainer SHAP pour RandomForest
explainer = shap.TreeExplainer(best_model)

# Calculer les valeurs SHAP
sample_size = len(X_test)
X_test_sample = X_test.iloc[:sample_size]

print(f"Calcul SHAP sur {sample_size} échantillons...")
shap_values = explainer.shap_values(X_test_sample)

# Vérifier la structure
print(f"Type de shap_values: {type(shap_values)}")
print(f"Shape originale: {shap_values.shape}")

# CONVERSION FORCÉE vers le format liste multi-classes
if shap_values.shape == (sample_size, len(X.columns), 3):
    print("🔄 Conversion vers format liste multi-classes...")
    
    # Convertir (sample_size, features, 3) vers liste de 3 arrays (sample_size, features)
    shap_values_converted = [
        shap_values[:, :, 0],  # Classe Fibre
        shap_values[:, :, 1],  # Classe Mobile
        shap_values[:, :, 2]   # Classe Wi-Fi
    ]
    
    # Remplacer la variable originale
    shap_values = shap_values_converted
    
    print("✅ Conversion réussie !")
    print(f"Nouveau type: {type(shap_values)}")
    print(f"Nombre de classes: {len(shap_values)}")
    print(f"Shape de chaque classe: {[sv.shape for sv in shap_values]}")

# Analyse SHAP
if isinstance(shap_values, list) and len(shap_values) == 3:
    print("✅ Structure SHAP correcte détectée")
    
    # 1. Summary plot global
    plt.figure(figsize=(12, 8))
    shap.summary_plot(shap_values, X_test_sample, feature_names=X.columns, 
                     class_names=label_encoder.classes_, show=False)
    plt.title("SHAP Summary Plot - Importance des features par classe")
    plt.tight_layout()
    plt.savefig('shap_summary_plot.png', dpi=150, bbox_inches='tight')
    plt.close()
    
    # 2. Importance globale
    plt.figure(figsize=(12, 8))
    global_importance = np.mean([np.abs(shap_values[i]).mean(axis=0) for i in range(3)], axis=0)
    
    feature_importance_df = pd.DataFrame({
        'feature': X.columns,
        'importance': global_importance
    }).sort_values('importance', ascending=True)
    
    plt.barh(feature_importance_df['feature'], feature_importance_df['importance'])
    plt.title("Importance Globale des Features TCP (SHAP)")
    plt.xlabel("Importance SHAP moyenne")
    plt.tight_layout()
    plt.savefig('shap_feature_importance.png', dpi=150, bbox_inches='tight')
    plt.close()
    
    # 3. Analyse par classe
    class_importance = {}
    for i, class_name in enumerate(label_encoder.classes_):
        mean_abs_shap = np.abs(shap_values[i]).mean(axis=0)
        class_importance[class_name] = dict(zip(X.columns, mean_abs_shap))
    
    print("\n=== TOP 5 FEATURES PAR CLASSE ===")
    for class_name, importance in class_importance.items():
        print(f"\n{class_name}:")
        sorted_features = sorted(importance.items(), key=lambda x: x[1], reverse=True)[:5]
        for feature, score in sorted_features:
            print(f"  {feature}: {score:.4f}")
    
    # 4. Exemple d'explication individuelle
    print("\n=== EXEMPLE D'EXPLICATION INDIVIDUELLE ===")
    print("Échantillon 0 - Contributions SHAP par classe:")
    
    for i, class_name in enumerate(label_encoder.classes_):
        print(f"\n{class_name}:")
        contributions = shap_values[i][0]  # Premier échantillon
        feature_contributions = list(zip(X.columns, contributions))
        sorted_contribs = sorted(feature_contributions, key=lambda x: abs(x[1]), reverse=True)[:5]
        
        for feature, contrib in sorted_contribs:
            print(f"  {feature}: {contrib:+.4f}")

print("\n=== ANALYSE TERMINÉE ===")
print("Graphiques sauvegardés dans le répertoire courant.")