# 🚀 Vercel Deployment Guide - Sentinel-X Website

## ✅ Fixed Issues

1. **404 Error Fixed**: Added root-level `vercel.json` to point to `security-ai-main/` subdirectory
2. **Button Updated**: Changed from "Coming Soon" to "Contribute on GitHub"
3. **GitHub Redirect**: Button now links to https://github.com/NOTANHUMAN-00/security-ai

---

## 📋 Deployment Steps

### Option 1: Automatic Deployment (Recommended)

1. **Go to Vercel**: https://vercel.com
2. **Import Project**: Click "Add New" → "Project"
3. **Connect GitHub**: Select your repository: `NOTANHUMAN-00/security-ai`
4. **Configure**:
   - Vercel will auto-detect the `vercel.json` configuration
   - Root Directory: Leave blank (vercel.json handles it)
   - Framework Preset: Create React App
   - Build Command: `cd security-ai-main && npm install && npm run build`
   - Output Directory: `security-ai-main/build`
5. **Deploy**: Click "Deploy"

### Option 2: Vercel CLI

```bash
# Install Vercel CLI
npm install -g vercel

# Login
vercel login

# Deploy from root directory
cd "C:\Users\markm\OneDrive\Desktop\the tunnel project security\sentinel-x"
vercel --prod
```

### Option 3: Deploy Only Website Folder

If the root deployment still has issues:

```bash
# Navigate to website folder
cd "C:\Users\markm\OneDrive\Desktop\the tunnel project security\sentinel-x\security-ai-main"

# Deploy this folder directly
vercel --prod
```

---

## 🔧 Configuration Files

### Root `/vercel.json`
```json
{
    "buildCommand": "cd security-ai-main && npm install && npm run build",
    "outputDirectory": "security-ai-main/build",
    "devCommand": "cd security-ai-main && npm start",
    "installCommand": "cd security-ai-main && npm install",
    "framework": null,
    "rewrites": [
        {
            "source": "/(.*)",
            "destination": "/index.html"
        }
    ]
}
```

This tells Vercel:
- Build the React app in the `security-ai-main/` subdirectory
- Output the build to `security-ai-main/build`
- Handle SPA routing with rewrites

---

## ✅ What's Been Done

1. ✅ **Button Updated** in `security-ai-main/src/components/Hero.js`:
   - Old: `Coming Soon` (disabled link)
   - New: `Contribute on GitHub` (links to GitHub repo)

2. ✅ **Vercel Config Added** at root level to handle subdirectory deployment

3. ✅ **Pushed to GitHub**: All changes are live at https://github.com/NOTANHUMAN-00/security-ai

---

## 🧪 Test Locally Before Deploying

```bash
# Navigate to website
cd "C:\Users\markm\OneDrive\Desktop\the tunnel project security\sentinel-x\security-ai-main"

# Install dependencies
npm install

# Start dev server
npm start

# Should open at http://localhost:3000
# Click "Contribute on GitHub" button to verify redirect works
```

---

## 🐛 Troubleshooting

### If you still get 404 on Vercel:

**Option A: Redeploy**
1. Go to Vercel dashboard
2. Select your deployment
3. Click "Redeploy" to use the new vercel.json

**Option B: Deploy Subdirectory Directly**
1. In Vercel project settings
2. Set "Root Directory" to `security-ai-main`
3. Redeploy

**Option C: Environment Variables**
If needed, add in Vercel dashboard:
- `NODE_VERSION`: `18.x`
- `NPM_VERSION`: `9.x`

---

## 📱 Expected Result

When deployed successfully:

1. **Homepage** loads at your Vercel URL
2. **"Contribute on GitHub"** button is visible (primary blue button)
3. **Clicking button** redirects to: https://github.com/NOTANHUMAN-00/security-ai
4. **Watch Demo** button shows video modal (coming soon message)

---

## 🔗 Links

- **Repository**: https://github.com/NOTANHUMAN-00/security-ai
- **Vercel Dashboard**: https://vercel.com/dashboard
- **Documentation**: See README_ROOT.md for project structure

---

## ✨ Summary

The website is now ready for deployment with:
- ✅ Button changed from "Coming Soon" to "Contribute on GitHub"
- ✅ Proper GitHub redirect (https://github.com/NOTANHUMAN-00/security-ai)
- ✅ Vercel configuration fixed for subdirectory deployment
- ✅ All changes pushed to GitHub

Just redeploy on Vercel and it should work! 🚀
