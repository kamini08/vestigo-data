import { Shield, Github, Twitter, Linkedin } from "lucide-react";

export const Footer = () => {
  return (
    <footer className="bg-card border-t border-border">
      <div className="container mx-auto px-6 py-12">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-8">
          {/* Brand */}
          <div className="col-span-1 md:col-span-2">
            <div className="flex items-center gap-2 mb-4">
              <Shield className="w-6 h-6 text-primary" />
              <span className="text-xl font-display font-bold">
                VESTI<span className="text-primary">GO</span>
              </span>
            </div>
            <p className="text-muted-foreground max-w-sm">
              AI/ML-based firmware cryptanalysis platform for detecting cryptographic 
              primitives, protocols, and key-schedules inside multi-architecture 
              binaries. Designed for researchers, auditors, and embedded security teams.
            </p>
          </div>

          {/* Platform Links */}
          <div>
            <h4 className="font-display font-semibold mb-4">Platform</h4>
            <ul className="space-y-2">
              <li>
                <a
                  href="/how-it-works"
                  className="text-muted-foreground hover:text-primary transition-colors"
                >
                  How VESTIGO Works
                </a>
              </li>
              <li>
                <a
                  href="/upload"
                  className="text-muted-foreground hover:text-primary transition-colors"
                >
                  Upload Firmware
                </a>
              </li>
              <li>
                <a
                  href="/jobs"
                  className="text-muted-foreground hover:text-primary transition-colors"
                >
                  Analysis Jobs
                </a>
              </li>
            </ul>
          </div>

          {/* Company */}
          <div>
            <h4 className="font-display font-semibold mb-4">Company</h4>
            <ul className="space-y-2">
              <li>
                <a
                  href="#"
                  className="text-muted-foreground hover:text-primary transition-colors"
                >
                  About VESTIGO
                </a>
              </li>
              <li>
                <a
                  href="#"
                  className="text-muted-foreground hover:text-primary transition-colors"
                >
                  Research & Blog
                </a>
              </li>
              <li>
                <a
                  href="#"
                  className="text-muted-foreground hover:text-primary transition-colors"
                >
                  Contact Team
                </a>
              </li>
            </ul>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="pt-8 border-t border-border flex flex-col md:flex-row justify-between items-center gap-4">
          <p className="text-muted-foreground text-sm">
            © 2025 VESTIGO. All rights reserved.
          </p>

          <div className="flex gap-4">
            <a
              href="#"
              className="text-muted-foreground hover:text-primary transition-colors"
            >
              <Github className="w-5 h-5" />
            </a>
            <a
              href="#"
              className="text-muted-foreground hover:text-primary transition-colors"
            >
              <Twitter className="w-5 h-5" />
            </a>
            <a
              href="#"
              className="text-muted-foreground hover:text-primary transition-colors"
            >
              <Linkedin className="w-5 h-5" />
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;