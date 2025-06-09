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


df = pd.read_csv('data.csv')

label_encoder = LabelEncoder()

df['Label_encoded'] = label_encoder.fit_transform(df['Label'])

print("Mapping des labels:")
for i, label in enumerate(label_encoder.classes_):
    print(f"{i}: {label}")

X = df.drop(['Label', 'Label_encoded'], axis=1)  # Features (toutes les colonnes sauf Label)
y_encoded = df['Label_encoded']  # Target (colonne Label)
y_original = df['Label']

X_train, X_test, y_train_enc, y_test_enc, y_train_orig, y_test_orig = train_test_split(X, y_encoded, y_original, test_size=0.2, random_state=42, stratify=y_encoded)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# Tester plusieurs modèles et comparer les performances
models = {
    'RandomForest': RandomForestClassifier(n_estimators=100, random_state=42),
    'XGBoost': XGBClassifier(random_state=42, eval_metric='logloss'),
    'SVM': SVC(kernel='rbf', random_state=42),
    'MLP': MLPClassifier(hidden_layer_sizes=(100, 50), random_state=42)
}




results = {}

skf_mixed = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

for name, model in models.items():
    print(f"\n=== {name} ===")

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


    model.fit(X_train_model, y_train_model)

    y_pred = model.predict(X_test_model)

    cv_scores = cross_val_score(model, X_train_model, y_train_model, cv=skf_mixed)

    results[name] = {
        'model': model,
        'cv_mean': cv_scores.mean(),
        'cv_std': cv_scores.std(),
        'predictions': y_pred
    }

    print(f"Cross-validation: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
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
    print(f"{name}: {result['cv_mean']:.4f} (+/- {result['cv_std'] * 2:.4f})")


best_model = results['RandomForest']['model']

print("\n=== ANALYSE SHAP EN COURS ===")

# Créer l'explainer SHAP pour RandomForest
explainer = shap.TreeExplainer(best_model)

# Calculer les valeurs SHAP sur un échantillon plus petit pour débugger
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
    
    # Convertir (100, 17, 3) vers liste de 3 arrays (100, 17)
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

# Maintenant le reste de votre code fonctionnera avec le format liste
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
    
    # 2. Importance globale (moyenne des valeurs absolues)
    plt.figure(figsize=(12, 8))
    
    # Calculer l'importance moyenne pour toutes les classes
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
    
    # 4. Graphique comparatif par classe
    fig, axes = plt.subplots(1, 3, figsize=(20, 8))
    for i, class_name in enumerate(label_encoder.classes_):
        top_features = sorted(class_importance[class_name].items(), 
                            key=lambda x: x[1], reverse=True)[:10]
        features, scores = zip(*top_features)
        
        axes[i].barh(range(len(features)), scores)
        axes[i].set_yticks(range(len(features)))
        axes[i].set_yticklabels(features)
        axes[i].set_title(f'Top 10 Features - {class_name}')
        axes[i].set_xlabel('Importance SHAP')
    
    plt.tight_layout()
    plt.savefig('shap_comparison_by_class.png', dpi=150, bbox_inches='tight')
    plt.close()
    
    # 5. BONUS : Exemple d'explication individuelle
    print("\n=== EXEMPLE D'EXPLICATION INDIVIDUELLE ===")
    print("Échantillon 0 - Contributions SHAP par classe:")
    
    for i, class_name in enumerate(label_encoder.classes_):
        print(f"\n{class_name}:")
        contributions = shap_values[i][0]  # Premier échantillon
        feature_contributions = list(zip(X.columns, contributions))
        # Trier par contribution absolue décroissante
        sorted_contribs = sorted(feature_contributions, key=lambda x: abs(x[1]), reverse=True)[:5]
        
        for feature, contrib in sorted_contribs:
            print(f"  {feature}: {contrib:+.4f}")

else:
    print("❌ Conversion échouée - utilisation du fallback RandomForest")
    
    # Fallback : utiliser l'importance native de RandomForest
    plt.figure(figsize=(12, 8))
    rf_importance = best_model.feature_importances_
    feature_importance_df = pd.DataFrame({
        'feature': X.columns,
        'importance': rf_importance
    }).sort_values('importance', ascending=True)
    
    plt.barh(feature_importance_df['feature'], feature_importance_df['importance'])
    plt.title("Feature Importance - RandomForest (natif)")
    plt.xlabel("Importance")
    plt.tight_layout()
    plt.savefig('rf_feature_importance.png', dpi=150, bbox_inches='tight')
    plt.close()
    
    print("\n=== TOP 5 FEATURES (RandomForest natif) ===")
    sorted_features = sorted(zip(X.columns, rf_importance), key=lambda x: x[1], reverse=True)[:5]
    for feature, score in sorted_features:
        print(f"  {feature}: {score:.4f}")

# Test avec validation croisée plus stricte
# Cross-validation plus rigoureuse
skf = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)
cv_scores_strict = cross_val_score(best_model, X, df['Label'], cv=skf)

print(f"CV strict (10-fold): {cv_scores_strict.mean():.4f} (+/- {cv_scores_strict.std() * 2:.4f})")
print(f"Scores individuels: {cv_scores_strict}")

print("\n=== ANALYSE TERMINÉE ===")
print("Graphiques sauvegardés dans le répertoire courant.")

print("\n" + "="*50)
print("=== TEST DE ROBUSTESSE ===")
print("="*50)

# Test avec validation croisée plus stricte
from sklearn.model_selection import StratifiedKFold

# Récupérer le meilleur modèle
best_model_name = max(results.keys(), key=lambda x: results[x]['cv_mean'])
print(f"Test sur le meilleur modèle: {best_model_name}")

# CORRECTION: Utiliser les bonnes données selon le modèle
if best_model_name == 'XGBoost':
    # XGBoost utilise les labels encodés
    X_for_test = X
    y_for_test = df['Label_encoded']
    model_for_test = results[best_model_name]['model']
elif best_model_name in ['SVM', 'MLP']:
    # SVM et MLP utilisent les données normalisées et labels originaux
    scaler_for_test = StandardScaler()
    X_for_test = scaler_for_test.fit_transform(X)
    y_for_test = df['Label']
    model_for_test = results[best_model_name]['model']
else:
    # RandomForest utilise les données brutes et labels originaux
    X_for_test = X
    y_for_test = df['Label']
    model_for_test = results[best_model_name]['model']

# Cross-validation plus rigoureuse
skf = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)
cv_scores_strict = cross_val_score(model_for_test, X_for_test, y_for_test, cv=skf)

print(f"\n=== RÉSULTATS VALIDATION CROISÉE STRICTE ===")
print(f"CV strict (10-fold): {cv_scores_strict.mean():.4f} (+/- {cv_scores_strict.std() * 2:.4f})")
print(f"Scores individuels: {cv_scores_strict}")

# Comparaison avec les résultats précédents
print(f"\n=== COMPARAISON ===")
print(f"CV précédent (5-fold): {results[best_model_name]['cv_mean']:.4f}")
print(f"CV strict (10-fold):   {cv_scores_strict.mean():.4f}")

difference = abs(cv_scores_strict.mean() - results[best_model_name]['cv_mean'])
print(f"Différence: {difference:.4f}")

if difference > 0.05:  # 5% de différence
    print("⚠️  ATTENTION: Grande différence détectée - possible surajustement")
elif cv_scores_strict.mean() > 0.98:
    print("⚠️  ATTENTION: Performance suspecte - vérifier data leakage")
else:
    print("✅ Performance cohérente")

# Test de stabilité
print(f"\n=== STABILITÉ ===")
print(f"Écart-type des scores: {cv_scores_strict.std():.4f}")
if cv_scores_strict.std() < 0.02:
    print("✅ Modèle très stable")
elif cv_scores_strict.std() < 0.05:
    print("✅ Modèle stable")  
else:
    print("⚠️  Modèle instable - performance variable")