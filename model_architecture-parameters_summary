## Model Architecture & Parameters Summary

| **Model** | **RandomForest** | **XGBoost** | **SVM (RBF)** | **MLP** |
|-----------|------------------|-------------|---------------|---------|
| **Type** | Ensemble/Bagging | Gradient Boosting | Kernel Method | Neural Network |
| **Architecture** | 100 independent trees | Sequential tree boosting | RBF kernel mapping | Input(12)→Hidden(100)→Hidden(50)→Output(4) |
| **Algorithm** | Bootstrap + Vote | Gradient descent | Support vectors | Backpropagation |

### Key Parameters

| **Parameter** | **RandomForest** | **XGBoost** | **SVM** | **MLP** |
|---------------|------------------|-------------|---------|---------|
| **n_estimators** | 100 | 100 | N/A | N/A |
| **max_depth** | None (unlimited) | 6 | N/A | N/A |
| **learning_rate** | N/A | 0.3 | N/A | 0.001 |
| **kernel** | N/A | N/A | 'rbf' | N/A |
| **C (regularization)** | N/A | reg_lambda=1 | 1.0 | alpha=0.0001 |
| **hidden_layers** | N/A | N/A | N/A | (100, 50) |
| **activation** | N/A | N/A | N/A | 'relu' |
| **solver** | N/A | N/A | N/A | 'adam'/'lbfgs' |
| **max_iter** | N/A | 100 rounds | N/A | 500 |

### Default Parameters Used

| **Model** | **Complete Parameter Set** |
|-----------|---------------------------|
| **RandomForest** | `n_estimators=100, max_depth=None, min_samples_split=2, min_samples_leaf=1, max_features='sqrt', bootstrap=True, criterion='gini'` |
| **XGBoost** | `n_estimators=100, max_depth=6, learning_rate=0.3, subsample=1.0, colsample_bytree=1.0, reg_alpha=0, reg_lambda=1, objective='multi:softprob'` |
| **SVM** | `kernel='rbf', C=1.0, gamma='scale', degree=3, coef0=0.0, shrinking=True, probability=False` |
| **MLP** | `hidden_layer_sizes=(100, 50), activation='relu', solver='adam', alpha=0.0001, batch_size='auto', learning_rate_init=0.001, max_iter=500` |

### Training Process

| **Model** | **Training Process** | **Multi-class Strategy** |
|-----------|---------------------|-------------------------|
| **RandomForest** | 1. Bootstrap sampling<br>2. Train 100 trees independently<br>3. Each tree uses √12≈3 random features<br>4. Majority vote prediction | Native multi-class |
| **XGBoost** | 1. Initialize with mean prediction<br>2. For each round (1-100):<br>   - Calculate gradients<br>   - Train tree on gradients<br>   - Add tree with learning_rate<br>3. Final = weighted sum | Native multi-class (softmax) |
| **SVM** | 1. RBF transformation: K(x,y)=exp(-γ‖x-y‖²)<br>2. Find optimal hyperplane<br>3. Identify support vectors<br>4. Solve quadratic optimization | One-vs-One (6 binary classifiers) |
| **MLP** | 1. Forward pass: Input→Hidden1→Hidden2→Output<br>2. Backward pass: Calculate gradients<br>3. Update weights using Adam/L-BFGS<br>4. Repeat until convergence | Native multi-class (softmax) |

### Model Characteristics

| **Aspect** | **RandomForest** | **XGBoost** | **SVM** | **MLP** |
|------------|------------------|-------------|---------|---------|
| **Complexity** | Medium | High | High | Very High |
| **Interpretability** | 3/5 | 2/5 | 1/5 | 1/5 |
| **Training Speed** | 3/5 | 3/5 | 2/5 | 2/5 |
| **Overfitting Risk** | Low | Medium | Medium | High |
| **Feature Scaling Required** | No | No | Yes | Yes |
| **Handles Non-linearity** | Yes | Yes | Yes (RBF) | Yes |
| **Memory Usage** | Medium | Medium | High | Low |
| **Hyperparameter Sensitivity** | Low | High | High | Very High |

### Prediction Method

| **Model** | **Prediction Logic** |
|-----------|---------------------|
| **RandomForest** | `prediction = majority_vote(tree1, tree2, ..., tree100)` |
| **XGBoost** | `prediction = sigmoid(∑(learning_rate × tree_i))` |
| **SVM** | `prediction = majority_vote(6_binary_classifiers)` |
| **MLP** | `prediction = softmax(W3×relu(W2×relu(W1×input)))` |
