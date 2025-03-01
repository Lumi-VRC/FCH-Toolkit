// Required modules
const express = require('express');
const axios = require('axios');
const qs = require('querystring');

const app = express();

// Replace these with your actual keys or use environment variables
const CLIENT_ID = 'id_here';
const CLIENT_SECRET = 'secret_here';
const REDIRECT_URI = 'https://fch-toolkit.com/auth/discord/callback';

// 1. Redirect to Discord's OAuth2 authorization URL
app.get('/auth/discord', (req, res) => {
  const params = qs.stringify({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: 'identify email'  // Adjust scopes as needed
  });
  const discordAuthUrl = `https://discord.com/api/oauth2/authorize?${params}`;
  res.redirect(discordAuthUrl);
});

// 2. Handle the OAuth2 callback from Discord
app.get('/auth/discord/callback', async (req, res) => {
  const code = req.query.code;
  if (!code) {
    return res.redirect('/login');  // Redirect to a login error page as needed
  }
  try {
    // 3. Exchange the authorization code for an access token
    const tokenResponse = await axios.post(
      'https://discord.com/api/oauth2/token',
      qs.stringify({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI
      }),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );
    const { access_token } = tokenResponse.data;

    // 4. Fetch user data from Discord
    const userResponse = await axios.get('https://discord.com/api/users/@me', {
      headers: {
        Authorization: `Bearer ${access_token}`
      }
    });
    const discordUser = userResponse.data;
    
    // 5. Create or update a local user in your database using discordUser info
    // For example:
    // const user = await User.findOrCreate({ discordId: discordUser.id, username: discordUser.username, ... });
    // Set session cookie or JWT token, etc.
    
    // Redirect the user to their dashboard or home page after login
    res.redirect('/dashboard');
  } catch (error) {
    console.error('Discord OAuth Error:', error);
    res.redirect('/login');
  }
});

// Start your server
app.listen(3000, () => {
  console.log('Server running on port 3000');
});
