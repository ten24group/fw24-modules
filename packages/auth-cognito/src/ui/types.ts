// UIConfig import
import type { IAuthModuleConfig } from '../interfaces';

// UIConfig reflects the subset of IAuthModuleConfig['ui'] required at runtime
export type UIConfig = Pick<NonNullable<IAuthModuleConfig['ui']>,
  'apiBaseUrl' |
  'theme' |
  'features' |
  'i18n'
>; 