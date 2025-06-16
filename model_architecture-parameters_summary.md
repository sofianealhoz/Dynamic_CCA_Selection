## Model Architecture & Parameters Summary

| **Model** | **RandomForest** | **XGBoost** | **SVM (RBF)** | **MLP** |
|-----------|------------------|-------------|---------------|---------|
| **Type** | Ensemble/Bagging | Gradient Boosting | Kernel Method | Neural Network |
| **Architecture** | 100 independent trees | Sequential tree boosting | RBF kernel mapping | Input(12)→Hidden(100)→Hidden(50)→Output(4) |
| **Algorithm** | Bootstrap + Vote | Gradient descent | Support vectors | Backpropagation |

## **Model Parameters**

| **Model** | **Architecture Parameters** | **Training Parameters** | **Regularization Parameters** |
|-----------|---------------------------|------------------------|------------------------------|
| **RandomForest** | `n_estimators=100`<br>`max_depth=None`<br>`min_samples_split=2`<br>`min_samples_leaf=1`<br>`max_features='sqrt'`<br>`bootstrap=True` | `criterion='gini'`<br>`random_state=42` | `max_samples=None`<br>`class_weight=None` |
| **XGBoost** | `n_estimators=100`<br>`max_depth=6`<br>`subsample=1.0`<br>`colsample_bytree=1.0` | `learning_rate=0.3`<br>`objective='multi:softprob'`<br>`eval_metric='logloss'`<br>`random_state=42` | `reg_alpha=0`<br>`reg_lambda=1`<br>`gamma=0`<br>`min_child_weight=1` |
| **SVM** | `kernel='rbf'`<br>`degree=3`<br>`coef0=0.0`<br>`gamma='scale'` | `shrinking=True`<br>`probability=False`<br>`random_state=42` | `C=1.0`<br>`tol=0.001`<br>`cache_size=200` |
| **MLP** | `hidden_layer_sizes=(100, 50)`<br>`activation='relu'`<br>`solver='adam'` | `learning_rate='constant'`<br>`learning_rate_init=0.001`<br>`batch_size='auto'`<br>`shuffle=True`<br>`random_state=42`<br>`max_iter=500` | `alpha=0.0001`<br>`momentum=0.9`<br>`beta_1=0.9`<br>`beta_2=0.999`<br>`epsilon=1e-08` |

### Training Process

| **Model** | **Training Process** | **Multi-class Strategy** |
|-----------|---------------------|-------------------------|
| **RandomForest** | 1. Bootstrap sampling<br>2. Train 100 trees independently<br>3. Each tree uses √12≈3 random features<br>4. Majority vote prediction | Native multi-class |
| **XGBoost** | 1. Initialize with mean prediction<br>2. For each round (1-100):<br>   - Calculate gradients<br>   - Train tree on gradients<br>   - Add tree with learning_rate<br>3. Final = weighted sum | Native multi-class (softmax) |
| **SVM** | 1. RBF transformation: K(x,y)=exp(-γ‖x-y‖²)<br>2. Find optimal hyperplane<br>3. Identify support vectors<br>4. Solve quadratic optimization | One-vs-One (6 binary classifiers) |
| **MLP** | 1. Forward pass: Input→Hidden1→Hidden2→Output<br>2. Backward pass: Calculate gradients<br>3. Update weights using Adam/L-BFGS<br>4. Repeat until convergence | Native multi-class (softmax) |

### Prediction Method

| **Model** | **Prediction Logic** |
|-----------|---------------------|
| **RandomForest** | `prediction = majority_vote(tree1, tree2, ..., tree100)` |
| **XGBoost** | `prediction = sigmoid(∑(learning_rate × tree_i))` |
| **SVM** | `prediction = majority_vote(6_binary_classifiers)` |
| **MLP** | `prediction = softmax(W3×relu(W2×relu(W1×input)))` |






-----------------------------------------------------------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------------------------------------------------------

## **Personnal explenations...**

### **RandomForest**
- **100 independent trees** that vote for the final prediction
- **Bootstrap sampling**: each tree trains on a different version of the data
- **max_features='sqrt'**: each split only considers 3 random features (out of 12)
- **criterion='gini'**: measures split purity (0=pure, 0.75=chaos)
- **No iterations**: builds all trees in parallel
- **No learning rate**: simple democratic vote
- **Robust to overfitting** thanks to randomization

### **XGBoost**
- **100 sequential trees** that correct each other
- **Gradient boosting**: each tree corrects errors from the previous one
- **100 iterations** even with full batch (progressive improvement)
- **learning_rate=0.3**: size of corrections to avoid over-fitting
- **subsample=1.0**: uses 100% of samples per tree
- **colsample_bytree=1.0**: uses 100% of features per tree
- **reg_lambda=1**: L2 regularization to prevent overfitting
- **objective='multi:softprob'**: optimizes for 4-class classification

### **SVM**
- **RBF kernel** transforms data to infinite-dimensional space
- **K(x,y) = exp(-γ||x-y||²)**: measures similarity based on distance
- **gamma='scale'**: RBF width automatically adapted to data
- **C=1.0**: balances training errors and generalization
- **6 binary classifiers** for 4 classes (One-vs-One)
- **degree=3 and coef0=0.0** ignored with RBF kernel
- **probability=False**: no probability computation (faster)

### **MLP (Neural Network)**
- **Architecture**: Input(12) → Hidden(100) → Hidden(50) → Output(4)
- **6,554 parameters** to optimize in total
- **activation='relu'**: f(x)=max(0,x) for hidden layers
- **500 epochs** maximum with possible early stopping
- **solver='adam'**: adaptive optimizer with momentum
- **batch_size=200**: processes in mini-batches of 200 samples
- **Backpropagation** computes gradients, **Adam** updates weights
- **alpha=0.0001**: light L2 regularization

### **Cross-Model Concepts**
- **Full batch** = uses entire dataset at each iteration
- **Learning rate** = step size, independent of batch size
- **Iterations ≠ epochs**: XGBoost does 100 rounds, MLP up to 500 epochs
- **Regularization**: prevents overfitting (L1, L2, dropout, etc.)
- **Data leakage**: when model sees answers in advance (connection_id)
- **Cross-validation > single test** to assess robustness

### **Key Differences**
- **RandomForest**: parallel, majority vote, overfitting resistant
- **XGBoost**: sequential, error correction, high performance
- **SVM**: kernel trick, optimal for medium non-linear data
- **MLP**: representation learning, flexible but complex

### **Attention Points**
- **connection_id_encoded** causes data leakage (artificial 100% performance)
- **Split by connection** necessary for realistic validation
- **Normalization required** for SVM and MLP only
- **Gradient descent ≠ backpropagation**: optimization vs gradient computation
- **RBF mapping**: implicit transformation to high-dimensional space

### **Expected Performance**
- **Perfect scores (100%)** = probable data leakage
- **Cross-validation** more reliable than single test
- **Realistic scores**: 80-95% after leakage correction
- **RandomForest** generally more stable
- **XGBoost** often better raw performance



Model Characteristics
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


