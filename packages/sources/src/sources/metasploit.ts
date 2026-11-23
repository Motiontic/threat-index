import { src } from '../define';

// Heavy, not git: the index is one 11 MB file, and a git first run would download the whole framework archive, exploit code included.
export default src('metasploit', 'Metasploit', 'Weaponised exploit exists', 'heavy', '3h', 'on', {
  heavy: true,
  parser: 'metasploit',
  pull: {
    heavy: {
      url: 'https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json',
    },
    jobKind: 'first-load',
  },
});
