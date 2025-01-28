export interface X509Callbacks {
  getX509SanDnsNames: (certificate: string) => string[]
  getX509SanUriNames: (certificate: string) => string[]
}
