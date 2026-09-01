import { signInSyntheticM2User } from './m2-auth-client.js';

const [authUrl, email] = process.argv.slice(2);
const projectPublishableKey = process.env.M2_PUBLISHABLE_KEY;
if (!authUrl || !email || !projectPublishableKey) {
  process.stderr.write('Synthetic local Auth sign-in configuration is incomplete.\n');
  process.exit(2);
}

try {
  const accessToken = await signInSyntheticM2User({
    authUrl,
    projectPublishableKey,
    email,
    password: 'SmpStrongPass!1',
  });
  process.stdout.write(accessToken);
} catch {
  process.stderr.write('Synthetic local Auth sign-in failed.\n');
  process.exit(1);
}
