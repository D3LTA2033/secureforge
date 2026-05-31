import debianFakeTwin from '../debian/faketwinlogin.js';

// Ubuntu ships libpam-duress in universe — identical approach, different PPAs sometimes needed
export default {
  ...debianFakeTwin,
  name: 'Fake Twin Login (Duress)',
  description: 'Two passwords — real OS vs decoy session. Uses libpam-duress from Ubuntu universe.',

  generate(config) {
    const base = debianFakeTwin.generate(config);
    return `
# Enable universe repo (required for libpam-duress on some Ubuntu versions)
add-apt-repository -y universe 2>/dev/null || true
apt-get update -qq

${base}
`;
  },
};
