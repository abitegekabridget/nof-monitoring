# NOF Monitoring Log - Netlify (free plan), logins without a database

- **Logins:** no database. The accounts are written in one Netlify setting called `USERS` (passwords are stored as codes, not readable).
- **Entries** (the daily log) are saved in Netlify Blobs, built into Netlify. Nothing else to sign up for except a free GitHub account.

## Step 1 - Put the files on GitHub
1. Sign up at github.com (free). Click **New repository**, name it `nof-monitoring`, choose **Private**, click **Create repository**.
2. Click **uploading an existing file**.
3. Unzip this package. Open the `nof-netlify` folder, select EVERYTHING inside it (`netlify` folder, `public` folder, `netlify.toml`, `package.json`, `README.md`) and drag it all into GitHub.
   Check that `netlify/functions/api.mjs` and `public/index.html` are in the list. Click **Commit changes**.

## Step 2 - Make the accounts
1. On your computer open the unzipped folder > `public` > double-click **make-user.html** (opens in Chrome or Edge).
2. For each person: type a username (e.g. `dorothy`), a password (8+ characters), choose Officer or Admin, press **Make line**. Make one Admin and one line per officer. (Make a second Admin as a spare.)
3. The box fills with lines like `dorothy:officer:3fa9...:77c1...`. Keep this box open or copy all of it into a note. Separate the lines with commas (the page already does this).
Tell each person their password privately.

## Step 3 - Create the site on Netlify
1. Sign up/log in at netlify.com (free plan). Click **Add new project > Import an existing project > GitHub** and pick `nof-monitoring`. Leave the build settings alone.
2. Before deploying, open **Environment variables** and add two:
   - `SESSION_SECRET` = a long random text, at least 32 characters (make up your own, never share it)
   - `USERS` = paste all the lines from step 2
3. Click **Deploy**. When it finishes you get a web address.

## Who can do what
- Officer: Daily log. Adds entries, marks their own issues Resolved/Reopen. Cannot delete.
- Admin: also sees "NOF view / monthly report" and can delete entries.
- Every entry records who logged it.

## Adding, removing or changing a person later
In Netlify: **Project configuration > Environment variables > USERS**, edit it (add a line from make-user.html, delete a line to remove someone, replace a line to change a password), save, then press **Deploys > Trigger deploy**. A person whose password was changed or whose line was removed is logged out automatically.

## What you give up by having no database for logins
- People cannot change their own password; the admin does it through `USERS`.
- No in-app user screen; users are managed in the Netlify setting.
- There is no lockout after wrong passwords (nothing stores the count). Each wrong attempt is slowed by a short delay, and passwords are stored hashed, so use passwords of 8+ characters that are not guessable.

## Good to know
- The page refreshes when you open it, every 5 minutes while visible, and when you press **Refresh** (to save your free allowance).
- Blobs has no automatic export: once a month save the "All NOFs" report as a PDF as your record.
- Netlify's free plan has a monthly usage allowance; if exceeded, the site is paused until the month ends. Check **Usage** now and then.
- To change the NOF list or series, edit the `RAW` text near the top of the script in `public/index.html` on GitHub (pencil icon) and commit.
