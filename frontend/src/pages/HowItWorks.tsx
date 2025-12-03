import { Upload, Cpu, FileCheck, Shield, Zap, Database, ArrowRight, CheckCircle2 } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Navbar } from "@/components/Navbar";
import { Footer } from "@/components/Footer";
import { motion } from "framer-motion";
import { Link } from "react-router-dom";
import analysisProcess from "@/assets/analysis-process.png";
import threatIntel from "@/assets/threat-intel.png";
import shieldImage from "@/assets/shield-3d.png";

const fadeInUp = {
  initial: { opacity: 0, y: 30 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.6, ease: "easeOut" }
};

const staggerContainer = {
  animate: {
    transition: { staggerChildren: 0.1 }
  }
};

const HowItWorks = () => {
  const steps = [
    {
      step: "01",
      title: "Firmware Upload & Preprocessing",
      description:
        "Upload your firmware or binary file through VESTIGO’s secure interface. We support ELF, BIN, HEX, raw dumps, and extracted file systems from routers, IoT devices, industrial and automotive systems.",
      features: [
        "Auto-detect architecture (ARM, MIPS, AVR, RISC-V, x86)",
        "Extract filesystem (SquashFS, UBIFS, CPIO)",
        "Identify executable regions",
        "Secure hash & metadata validation"
      ],
      icon: Upload,
      image: null,
      iconBg: true
    },

    {
      step: "02",
      title: "Static & Dynamic Feature Extraction",
      description:
        "VESTIGO extracts opcode patterns, instruction sequences, CFG graphs, n-grams, entropy spikes, key-schedule patterns, and potential crypto constants using Ghidra, Radare2, capstone, objdump and QEMU emulation.",
      features: [
        "Opcode + n-gram extraction",
        "Entropy & S-box identification",
        "CFG graph construction",
        "QEMU-based dynamic trace"
      ],
      icon: Cpu,
      image: analysisProcess,
      iconBg: false
    },

    {
      step: "03",
      title: "ML Model Analysis & Crypto Detection",
      description:
        "Our GNN + Light GBM-based engine identifies cryptographic primitives, protocol phases, key-schedules, and obfuscation techniques present in stripped firmware binaries.",
      features: [
        "Detect AES / RSA / ECC / SHA / PRNG / XOR",
        "Cross-architecture opcode learning",
        "Identify unknown/proprietary crypto",
        "Protocol flow & handshake detection"
      ],
      icon: Database,
      image: threatIntel,
      iconBg: false
    },

    {
      step: "04",
      title: "Report Generation & Explainability",
      description:
        "VESTIGO generates a comprehensive analysis report including detected cryptographic functions, protocol states, key-materials nearby, CFG visualizations, opcode similarities and explainable ML insights.",
      features: [
        "Full crypto classification",
        "Explainable ML reasoning",
        "Key material indicators",
        "Export as PDF / JSON / API"
      ],
      icon: FileCheck,
      image: null,
      iconBg: true
    }
  ];

  const technologies = [
    {
      icon: Shield,
      title: "GNN + Light GBM Models",
      description: "Graph-based + sequence-aware neural networks trained on multi-architecture crypto datasets."
    },
    {
      icon: Zap,
      title: "Dynamic Emulation",
      description: "QEMU full-system emulation and runtime trace mapping for protocol state detection."
    },
    {
      icon: Database,
      title: "Crypto Intelligence",
      description: "Embedded crypto signatures, S-box patterns, key-schedule markers, and opcode embeddings."
    }
  ];

  return (
    <div className="min-h-screen bg-background overflow-hidden">
      <Navbar />

      {/* HERO */}
      <section className="pt-32 pb-20 px-6 relative">
        <div className="absolute inset-0 overflow-hidden">
          <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-primary/10 rounded-full blur-3xl" />
          <div className="absolute bottom-1/4 right-1/4 w-80 h-80 bg-cyber-blue/10 rounded-full blur-3xl" />
        </div>

        <div className="container mx-auto relative z-10">
          <motion.div
            className="max-w-4xl mx-auto text-center"
            initial={{ opacity: 0, y: 40 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.2, duration: 0.5 }}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 mb-6"
            >
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-primary"></span>
              </span>
              <span className="text-sm font-medium text-primary">
                VESTIGO Firmware Analysis Pipeline
              </span>
            </motion.div>

            <motion.h1
              className="text-5xl md:text-7xl font-display font-bold mb-6"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3, duration: 0.6 }}
            >
              How <span className="text-primary cyber-glow">VESTIGO</span> Works
            </motion.h1>

            <motion.p
              className="text-xl md:text-2xl text-muted-foreground max-w-2xl mx-auto"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.4, duration: 0.6 }}
            >
              A multi-stage ML framework that extracts, detects, and explains cryptographic algorithms
              inside multi-architecture firmware binaries.
            </motion.p>

            <motion.div
              className="mt-12 flex justify-center"
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.5, duration: 0.8, type: "spring" }}
            >
              <motion.img
                src={shieldImage}
                alt="Security Shield"
                className="w-32 h-32 md:w-40 md:h-40 object-contain drop-shadow-2xl"
                animate={{ y: [0, -10, 0] }}
                transition={{ duration: 3, repeat: Infinity, ease: "easeInOut" }}
              />
            </motion.div>
          </motion.div>
        </div>
      </section>

      {/* PIPELINE OVERVIEW */}
      <section className="py-20 px-6">
        <div className="container mx-auto">
          <div className="max-w-6xl mx-auto">
            {steps.map((step, index) => (
              <motion.div
                key={index}
                className="relative mb-24 last:mb-0"
                initial={{ opacity: 0, y: 50 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, margin: "-100px" }}
                transition={{ duration: 0.6, delay: index * 0.1 }}
              >
                <div
                  className={`grid grid-cols-1 lg:grid-cols-2 gap-12 items-center ${
                    index % 2 === 1 ? "lg:flex-row-reverse" : ""
                  }`}
                >
                  {/* CONTENT */}
                  <motion.div
                    className={index % 2 === 1 ? "lg:order-2" : ""}
                    initial={{ opacity: 0, x: index % 2 === 0 ? -30 : 30 }}
                    whileInView={{ opacity: 1, x: 0 }}
                    viewport={{ once: true }}
                    transition={{ duration: 0.6, delay: 0.2 }}
                  >
                    <motion.div
                      className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 mb-4"
                      whileHover={{ scale: 1.05 }}
                    >
                      <span className="text-sm font-bold text-primary">STEP {step.step}</span>
                    </motion.div>

                    <h2 className="text-3xl md:text-4xl font-display font-bold mb-4">
                      {step.title}
                    </h2>

                    <p className="text-lg text-muted-foreground mb-6">
                      {step.description}
                    </p>

                    <motion.ul
                      className="space-y-3"
                      variants={staggerContainer}
                      initial="initial"
                      whileInView="animate"
                      viewport={{ once: true }}
                    >
                      {step.features.map((item, featureIndex) => (
                        <motion.li
                          key={featureIndex}
                          className="flex items-center gap-3"
                          variants={fadeInUp}
                        >
                          <div className="w-6 h-6 rounded-full bg-primary/20 flex items-center justify-center">
                            <CheckCircle2 className="w-4 h-4 text-primary" />
                          </div>
                          <span className="text-muted-foreground">{item}</span>
                        </motion.li>
                      ))}
                    </motion.ul>
                  </motion.div>

                  {/* IMAGE / ICON */}
                  <motion.div
                    className={index % 2 === 1 ? "lg:order-1" : ""}
                    initial={{ opacity: 0, x: index % 2 === 0 ? 30 : -30 }}
                    whileInView={{ opacity: 1, x: 0 }}
                    viewport={{ once: true }}
                    transition={{ duration: 0.6, delay: 0.3 }}
                  >
                    <Card className="bg-card/50 border-border/50 p-6 backdrop-blur-sm overflow-hidden group hover:border-primary/50 transition-all duration-500">
                      {step.image ? (
                        <motion.div
                          className="rounded-lg overflow-hidden"
                          whileHover={{ scale: 1.02 }}
                          transition={{ duration: 0.3 }}
                        >
                          <img
                            src={step.image}
                            alt={step.title}
                            className="w-full h-64 object-cover rounded-lg"
                          />
                        </motion.div>
                      ) : (
                        <div className="flex items-center justify-center h-64 bg-gradient-to-br from-secondary/50 to-secondary/30 rounded-lg relative overflow-hidden">
                          <motion.div
                            className="absolute inset-0 bg-gradient-to-r from-primary/5 via-primary/10 to-primary/5"
                            animate={{ x: ["-100%", "100%"] }}
                            transition={{
                              duration: 3,
                              repeat: Infinity,
                              ease: "linear"
                            }}
                          />

                          <motion.div
                            whileHover={{ scale: 1.1, rotate: 5 }}
                            transition={{ duration: 0.3 }}
                          >
                            <step.icon className="w-24 h-24 text-primary relative z-10" />
                          </motion.div>
                        </div>
                      )}
                    </Card>
                  </motion.div>
                </div>

                {/* CONNECTOR LINE */}
                {index < steps.length - 1 && (
                  <motion.div
                    className="hidden lg:block absolute left-1/2 -bottom-12 transform -translate-x-1/2"
                    initial={{ opacity: 0, height: 0 }}
                    whileInView={{ opacity: 1, height: 48 }}
                    viewport={{ once: true }}
                    transition={{ duration: 0.5, delay: 0.5 }}
                  >
                    <div className="w-0.5 h-full bg-gradient-to-b from-primary to-primary/0" />
                    <motion.div
                      className="absolute -bottom-2 left-1/2 transform -translate-x-1/2 w-3 h-3 rounded-full bg-primary"
                      animate={{ scale: [1, 1.2, 1] }}
                      transition={{ duration: 2, repeat: Infinity }}
                    />
                  </motion.div>
                )}
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* TECHNOLOGY STACK */}
      <section className="py-24 px-6 relative">
        <div className="absolute inset-0 bg-gradient-to-b from-card/50 to-background" />
        <div className="absolute inset-0 cyber-grid opacity-30" />

        <div className="container mx-auto relative z-10">
          <motion.div
            className="max-w-4xl mx-auto text-center mb-16"
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true }}
              transition={{ delay: 0.1 }}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 border border-primary/20 mb-6"
            >
              <Zap className="w-4 h-4 text-primary" />
              <span className="text-sm font-medium text-primary">Technology Stack</span>
            </motion.div>

            <h2 className="text-4xl md:text-5xl font-display font-bold mb-4">
              Powered by <span className="text-primary">Advanced</span> Cryptanalysis
            </h2>
            <p className="text-xl text-muted-foreground">
              VESTIGO combines ML, graph processing, dynamic emulation and crypto intelligence.
            </p>
          </motion.div>

          <motion.div
            className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-5xl mx-auto"
            variants={staggerContainer}
            initial="initial"
            whileInView="animate"
            viewport={{ once: true }}
          >
            {technologies.map((tech, index) => (
              <motion.div
                key={index}
                variants={fadeInUp}
                whileHover={{ y: -8, transition: { duration: 0.2 } }}
              >
                <Card className="bg-card/80 backdrop-blur-sm border-border/50 p-8 h-full hover:border-primary/50 transition-all duration-300 group">
                  <motion.div
                    className="w-14 h-14 rounded-xl bg-primary/10 flex items-center justify-center mb-6 group-hover:bg-primary/20 transition-colors"
                    whileHover={{ rotate: 10, scale: 1.1 }}
                  >
                    <tech.icon className="w-7 h-7 text-primary" />
                  </motion.div>
                  <h3 className="text-xl font-display font-semibold mb-3">{tech.title}</h3>
                  <p className="text-muted-foreground">{tech.description}</p>
                </Card>
              </motion.div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-24 px-6 relative">
        <div className="absolute inset-0 overflow-hidden">
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-primary/10 rounded-full blur-3xl" />
        </div>

        <div className="container mx-auto relative z-10">
          <motion.div
            className="max-w-3xl mx-auto text-center"
            initial={{ opacity: 0, y: 30 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.5 }}
              whileInView={{ opacity: 1, scale: 1 }}
              viewport={{ once: true }}
              transition={{ delay: 0.2, type: "spring" }}
              className="mb-8"
            >
              <div className="w-20 h-20 mx-auto rounded-full bg-primary/10 flex items-center justify-center mb-6 animate-glow-pulse">
                <Shield className="w-10 h-10 text-primary" />
              </div>
            </motion.div>

            <h2 className="text-4xl md:text-5xl font-display font-bold mb-6">
              Ready to Analyze <span className="text-primary cyber-glow">Firmware</span>?
            </h2>
            <p className="text-xl text-muted-foreground mb-10">
              Upload any binary and uncover hidden cryptographic implementations instantly.
            </p>

            <motion.div whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.98 }}>
              <Link to="/upload">
                <Button
                  size="lg"
                  className="bg-primary hover:bg-primary/90 text-primary-foreground font-semibold text-lg px-10 py-6 rounded-xl shadow-lg shadow-primary/25 hover:shadow-xl hover:shadow-primary/30 transition-all"
                >
                  Upload Firmware Now
                  <ArrowRight className="ml-2 w-5 h-5" />
                </Button>
              </Link>
            </motion.div>
          </motion.div>
        </div>
      </section>

      <Footer />
    </div>
  );
};

export default HowItWorks;

