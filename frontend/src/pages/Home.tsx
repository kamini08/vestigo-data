import { Shield, Zap, Lock, Server, ArrowRight, CheckCircle2, Users, FileSearch } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Navbar } from "@/components/Navbar";
import { Footer } from "@/components/Footer";
import { motion } from "framer-motion";
import { Link } from "react-router-dom";
import heroCyber from "@/assets/hero-cyber.png";
import shield3d from "@/assets/shield-3d.png";

const fadeUpVariants = {
  hidden: { opacity: 0, y: 30 },
  visible: (delay = 0) => ({ opacity: 1, y: 0, transition: { duration: 0.6, delay, ease: "easeOut" } })
};

const staggerContainer = {
  hidden: { opacity: 0 },
  visible: { opacity: 1, transition: { staggerChildren: 0.1 } }
};

const cardVariants = {
  hidden: { opacity: 0, y: 20 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.5, ease: "easeOut" } }
};

const Home = () => {
  return (
    <div className="min-h-screen bg-background">
      <Navbar />

      {/* HERO SECTION */}
      <section className="relative pt-28 pb-20 px-6 overflow-hidden">
        <div className="absolute inset-0 cyber-grid opacity-10" />
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[800px] bg-primary/20 rounded-full blur-[150px] opacity-30" />
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-background/50 to-background" />

        <div className="container mx-auto relative z-10">
          <div className="grid lg:grid-cols-2 gap-12 items-center">

            {/* Left Content */}
            <motion.div initial="hidden" animate="visible" className="text-left">
              <motion.div
                variants={fadeUpVariants}
                custom={0}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-card/80 backdrop-blur border border-border mb-6"
              >
                <div className="w-2 h-2 rounded-full bg-primary animate-pulse" />
                <span className="text-sm text-muted-foreground">Empowering Firmware Security Through AI</span>
              </motion.div>
              

              <motion.h1
                variants={fadeUpVariants}
                custom={0.1}
                className="text-4xl md:text-6xl font-display font-bold mb-6 leading-tight"
              >
                <span className="text-primary cyber-glow">Vestigo</span>
                <p className="text-3xl md:text-4xl gap-2">Uncover Hidden Cryptography Inside Firmware</p>
                
              </motion.h1>

              <motion.p
                variants={fadeUpVariants}
                custom={0.2}
                className="text-lg text-muted-foreground mb-8 max-w-xl"
              >
                Upload any firmware or binary file and automatically detect embedded cryptographic algorithms,
                protocol patterns, and obfuscated crypto using advanced machine learning and graph-based analysis.
              </motion.p>

              <motion.div variants={fadeUpVariants} custom={0.3} className="flex flex-col sm:flex-row gap-4">
                <Button size="lg" asChild className="bg-primary hover:bg-primary/90 text-primary-foreground font-semibold text-lg px-8 animate-glow-pulse">
                  <Link to="/upload">Start Crypto Detection <ArrowRight className="ml-2 w-5 h-5" /></Link>
                </Button>
                <Button size="lg" variant="outline" asChild className="font-semibold text-lg px-8 border-border hover:border-primary hover:bg-primary/5">
                  <Link to="/how-it-works">How VESTIGO Works</Link>
                </Button>
              </motion.div>
            </motion.div>

            {/* Right Image */}
            <motion.div initial={{ opacity: 0, scale: 0.9, x: 50 }} animate={{ opacity: 1, scale: 1, x: 0 }} transition={{ duration: 0.8, delay: 0.2 }} className="relative hidden lg:block">
              <div className="relative">
                <div className="absolute inset-0 bg-gradient-to-r from-primary/30 to-cyber-blue/30 rounded-2xl blur-2xl" />
                <img src={heroCyber} alt="Firmware Crypto Dashboard" className="relative rounded-2xl border border-border/50 shadow-2xl" />
              </div>
            </motion.div>
          </div>
        </div>
      </section>

      {/* STATS SECTION */}
      <section className="py-16 px-6 relative">
        <div className="container mx-auto">
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true, margin: "-100px" }} variants={staggerContainer} className="grid grid-cols-2 md:grid-cols-4 gap-6">
            {[
              { icon: Shield, value: "94%+", label: "Crypto Detection F1-Score", color: "text-primary" },
              { icon: FileSearch, value: "72+", label: "Firmware Datasets", color: "text-cyber-blue" },
              { icon: Zap, value: "<5 min", label: "Avg Analysis Time", color: "text-primary" },
              { icon: Users, value: "20+", label: "Supported Architectures", color: "text-cyber-blue" }
            ].map((stat, index) => (
              <motion.div key={index} variants={cardVariants}>
                <Card className="bg-card/50 backdrop-blur border-border p-6 text-center hover:border-primary/50 transition-all duration-300 group">
                  <stat.icon className={`w-8 h-8 ${stat.color} mx-auto mb-3 group-hover:scale-110 transition-transform`} />
                  <div className="text-3xl md:text-4xl font-display font-bold text-foreground mb-1">{stat.value}</div>
                  <div className="text-sm text-muted-foreground">{stat.label}</div>
                </Card>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* FEATURES SECTION */}
      <section className="py-20 px-6 relative">
        <div className="container mx-auto">
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true, margin: "-100px" }} className="grid lg:grid-cols-2 gap-16 items-center">

            {/* Image Side */}
            <motion.div variants={fadeUpVariants} custom={0} className="relative order-2 lg:order-1">
              <div className="relative">
                <div className="absolute -inset-4 bg-gradient-to-r from-primary/20 to-transparent rounded-3xl blur-2xl" />
                <div className="relative bg-card/50 backdrop-blur rounded-2xl border border-border p-8">
                  <img src={shield3d} alt="Crypto Shield" className="w-full max-w-sm mx-auto animate-float" />
                </div>
              </div>
            </motion.div>

            {/* Content Side */}
            <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} className="order-1 lg:order-2">
              <motion.span variants={fadeUpVariants} custom={0} className="text-primary text-sm font-semibold uppercase tracking-wider">
                AI-Driven Firmware Cryptoanalysis
              </motion.span>

              <motion.h2 variants={fadeUpVariants} custom={0.1} className="text-3xl md:text-4xl font-display font-bold mt-3 mb-6">
                Core Capabilities of VESTIGO
              </motion.h2>

              <motion.p variants={fadeUpVariants} custom={0.2} className="text-muted-foreground mb-8">
                VESTIGO combines machine learning, graph neural networks, and dynamic emulation to detect
                cryptographic primitives, key-schedule patterns, obfuscation, and protocol flows within stripped
                firmware binaries.
              </motion.p>

              <motion.div variants={staggerContainer} className="grid grid-cols-2 gap-6">
                {[
                  { value: "6+", label: "Crypto Algorithms" },
                  { value: "5+", label: "Architectures Supported" },
                  { value: "3M+", label: "Instruction Patterns Learned" },
                  { value: "87%", label: "Cross-Arch Accuracy" }
                ].map((item, index) => (
                  <motion.div key={index} variants={cardVariants} className="bg-card/50 backdrop-blur rounded-xl border border-border p-4 hover:border-primary/50 transition-colors">
                    <div className="text-2xl font-display font-bold text-primary mb-1">{item.value}</div>
                    <div className="text-sm text-muted-foreground">{item.label}</div>
                  </motion.div>
                ))}
              </motion.div>
            </motion.div>
          </motion.div>
        </div>
      </section>

      {/* SERVICES SECTION */}
      <section className="py-20 px-6 bg-card/30">
        <div className="container mx-auto">
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} className="text-center mb-16">
            <motion.span variants={fadeUpVariants} custom={0} className="text-primary text-sm font-semibold uppercase tracking-wider">
              AI-Powered Firmware Insight
            </motion.span>

            <motion.h2 variants={fadeUpVariants} custom={0.1} className="text-3xl md:text-5xl font-display font-bold mt-3 mb-4">
              Intelligent Crypto Detection Features
            </motion.h2>

            <motion.p variants={fadeUpVariants} custom={0.2} className="text-xl text-muted-foreground max-w-2xl mx-auto">
              Built for security researchers, embedded analysts, and organizations analyzing proprietary firmware.
            </motion.p>
          </motion.div>

          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true, margin: "-50px" }} variants={staggerContainer} className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {[
              {
                icon: Shield,
                title: "Crypto Primitive Detection",
                description: "Automatically detect AES, RSA, ECC, SHA, PRNG, XOR and unknown crypto patterns.",
              },
              {
                icon: Zap,
                title: "Cross-Arch Opcode Learning",
                description: "ML models trained on ARM, AVR, MIPS, RISC-V, and x86 instruction sets.",
              },
              {
                icon: Lock,
                title: "Key Material Discovery",
                description: "Identify S-boxes, key-schedules, PRNG seeds, entropy spikes, and sensitive memory regions.",
              },
              {
                icon: Server,
                title: "Protocol Flow Analysis",
                description: "Detect handshake patterns, key exchange sequences, and signing operations in firmware.",
              }
            ].map((feature, index) => (
              <motion.div key={index} variants={cardVariants}>
                <Card className="bg-card border-border p-6 h-full hover:border-primary transition-all duration-300 group hover:-translate-y-1">
                  <div className="w-14 h-14 rounded-xl bg-primary/10 flex items-center justify-center mb-5 group-hover:bg-primary/20 group-hover:scale-110 transition-all duration-300">
                    <feature.icon className="w-7 h-7 text-primary" />
                  </div>
                  <h3 className="text-xl font-display font-semibold mb-3">{feature.title}</h3>
                  <p className="text-muted-foreground text-sm leading-relaxed">{feature.description}</p>
                </Card>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* HOW IT WORKS SECTION */}
      <section className="py-20 px-6">
        <div className="container mx-auto">
          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true }} className="text-center mb-16">
            <motion.span variants={fadeUpVariants} custom={0} className="text-primary text-sm font-semibold uppercase tracking-wider">
              Start Using VESTIGO
            </motion.span>

            <motion.h2 variants={fadeUpVariants} custom={0.1} className="text-3xl md:text-5xl font-display font-bold mt-3 mb-4">
              Simple 3-Step Firmware Analysis
            </motion.h2>

            <motion.p variants={fadeUpVariants} custom={0.2} className="text-xl text-muted-foreground">
              From upload to full crypto detection in minutes
            </motion.p>
          </motion.div>

          <motion.div initial="hidden" whileInView="visible" viewport={{ once: true, margin: "-50px" }} variants={staggerContainer} className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {[
              {
                step: "01",
                title: "Upload Firmware",
                description: "Upload any ELF, BIN, HEX, or extracted filesystem for analysis.",
                color: "from-primary/20 to-primary/5",
              },
              {
                step: "02",
                title: "ML-Based Crypto Detection",
                description: "Opcode, CFG, entropy, and signature extraction powered by ML models.",
                color: "from-cyber-blue/20 to-cyber-blue/5",
              },
              {
                step: "03",
                title: "Get Crypto Report",
                description: "Receive a structured report of detected algorithms, key regions, and protocol insights.",
                color: "from-primary/20 to-primary/5",
              }
            ].map((item, index) => (
              <motion.div key={index} variants={cardVariants}>
                <Card className={`relative bg-gradient-to-b ${item.color} border-border p-8 text-center h-full hover:border-primary/50 transition-all duration-300 group overflow-hidden`}>
                  <div className="absolute top-4 right-4 text-7xl font-display font-bold text-primary/10 group-hover:text-primary/20 transition-colors">
                    {item.step}
                  </div>
                  <div className="relative z-10">
                    <div className="w-16 h-16 rounded-full bg-primary/20 flex items-center justify-center mx-auto mb-6 group-hover:scale-110 transition-transform">
                      <span className="text-2xl font-display font-bold text-primary">{item.step}</span>

                    </div>
                    <h3 className="text-xl font-display font-semibold mb-3">
                      {item.title}
                    </h3>
                    <p className="text-muted-foreground text-sm">
                      {item.description}
                    </p>
                  </div>
                </Card>
              </motion.div>
            ))}
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.4 }}
            className="text-center mt-12"
          >
            <Button
              size="lg"
              asChild
              className="bg-primary hover:bg-primary/90 text-primary-foreground font-semibold px-8"
            >
              <Link to="/how-it-works">
                Learn More About VESTIGO <ArrowRight className="ml-2 w-5 h-5" />
              </Link>
            </Button>
          </motion.div>
        </div>
      </section>

      
      {/* CTA SECTION */}
      <section className="py-20 px-6 relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-r from-primary/10 via-cyber-blue/10 to-primary/10" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-primary/20 rounded-full blur-[150px] opacity-30" />

        <motion.div
          initial="hidden"
          whileInView="visible"
          viewport={{ once: true }}
          className="container mx-auto relative z-10"
        >
          <div className="max-w-3xl mx-auto text-center">
            <motion.h2
              variants={fadeUpVariants}
              custom={0}
              className="text-3xl md:text-5xl font-display font-bold mb-6"
            >
              Ready to Analyze Firmware with AI?
            </motion.h2>

            <motion.p
              variants={fadeUpVariants}
              custom={0.1}
              className="text-xl text-muted-foreground mb-8"
            >
              Join researchers and organizations using VESTIGO to uncover hidden
              cryptography inside black-box firmware binaries.
            </motion.p>

            <motion.div
              variants={fadeUpVariants}
              custom={0.2}
              className="flex flex-col sm:flex-row gap-4 justify-center"
            >
              <Button
                size="lg"
                asChild
                className="bg-primary hover:bg-primary/90 text-primary-foreground font-semibold text-lg px-8 animate-glow-pulse"
              >
                <Link to="/upload">Start Free Crypto Scan</Link>
              </Button>

              <Button
                size="lg"
                variant="outline"
                className="font-semibold text-lg px-8 border-border hover:border-primary hover:bg-primary/5"
              >
                Contact Enterprise Team
              </Button>
            </motion.div>
          </div>
        </motion.div>
      </section>

      <Footer />
    </div>
  );
};

export default Home;
