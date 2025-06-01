import pandas as pd

# Load dataset
df = pd.read_csv("phishing.csv")

# Separate phishing and safe sites
phishing_sites = df[df['class'] == 1]
safe_sites = df[df['class'] == -1]

# Reduce phishing sites to match safe sites (undersampling)
phishing_sites = phishing_sites.sample(len(safe_sites), random_state=42)

# Combine balanced data
balanced_df = pd.concat([phishing_sites, safe_sites])

# Shuffle data
balanced_df = balanced_df.sample(frac=1, random_state=42).reset_index(drop=True)

# Save new dataset
balanced_df.to_csv("balanced_phishing.csv", index=False)

print("✅ Balanced dataset saved as balanced_phishing.csv!")
print(balanced_df['class'].value_counts())  # Verify count

