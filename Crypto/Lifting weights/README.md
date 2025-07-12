# Solution des défis du Shutlock2025 édition 2

Bienvenue dans le dépôt de **Shutlock2025**.

## Enoncé du sujet
![image](assets/images/enonce.png)
![image](assets/images/execution.png)
![image](assets/images/solution.png)


## Fonctionnalités

- **La résolution de Lifting Weights fait appel au lemme de LTE ou Manea qui donne des formules pour calculer la valuation p-adique ${\displaystyle \nu _{p}}$ de certaines expressions entières et qui est applicable aux courbes elliptiques** : ReadMe.md et Lifting Weights (Fichier PDF).🖼️ 


## Fonctionnalités

- **La solution expliquée** : Lifting_Weights (Fichier PDF).

## Principe math
## 🧮 Extraction de l’octet via LTE

Pour chaque tuple $(r, f)$, la relation suivante est **exacte** :

$$
f = f(t) = \nu_{2}(x^n - y^n) = 2r \cdot b
$$

grâce au **lemme du relèvement des exposants (LTE)** ($p=2$)

$$
\nu_{2}(x^n - y^n) = \nu_{2}(x - y) + \nu_{2}(n)+ \nu_{2}(x + y) - 1,
$$

où  :

- $`n = 2^{r b}`$
- $`x - y = n`$


démontrant que les autres facteurs n’apportent rien à la valuation.  

➡️ **On obtient** :

$$
b = \frac{f}{2r}.
$$

## Installation

1. **Cloner le dépôt** :
   ```bash

   git clone https://github.com/JackeOLantern/Shutlock2025.git

...
