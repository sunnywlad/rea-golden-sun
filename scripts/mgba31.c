/* Local adapter for installed libmgba 0.10.5. No ROM modifications. */
#include <mgba/core/core.h>
#include <mgba/core/config.h>
#include <mgba/core/log.h>
#include <mgba/internal/arm/arm.h>
#include <stdlib.h>
#include <string.h>
static struct mCore *core;
static color_t pixels[240 * 160];
static void quiet(struct mLogger *l, int c, enum mLogLevel level, const char *f, va_list a) {}
static struct mLogger logger = { quiet, NULL };
int start(const char *path) {
  mLogSetDefaultLogger(&logger);
  core = mCoreFind(path);
  if (!core || !core->init(core)) return 0;
  mCoreInitConfig(core, NULL);
  mCoreConfigSetIntValue(&core->config, "idleOptimization", 0);
  core->loadConfig(core, &core->config);
  core->setVideoBuffer(core, pixels, 240);
  if (!mCoreLoadFile(core, path)) return 0;
  core->reset(core);
  return 1;
}
void frames(unsigned n, unsigned keys) {
  core->setKeys(core, keys);
  while (n--) core->runFrame(core);
}
void step(void) { core->step(core); }
unsigned until(unsigned limit, unsigned low, unsigned high) {
  struct ARMCore *cpu = core->cpu;
  for (unsigned n = 0; n < limit; ++n) {
    if ((cpu->cpsr.packed & 31) == 31 && (unsigned)cpu->gprs[15] >= low && (unsigned)cpu->gprs[15] < high) return n;
    core->step(core);
  }
  return limit;
}
unsigned rd(unsigned a, unsigned width) {
  if (width == 1) return core->busRead8(core, a);
  if (width == 2) return core->busRead16(core, a);
  return core->busRead32(core, a);
}
unsigned raw16(unsigned a) { return core->rawRead16(core, a, -1); }
void wr(unsigned a, unsigned v, unsigned width) {
  if (width == 1) core->busWrite8(core, a, v);
  else if (width == 2) core->busWrite16(core, a, v);
  else core->busWrite32(core, a, v);
}
int regset(const char *name, unsigned val) { return core->writeRegister(core, name, &val); }
unsigned regget(const char *name) {
  unsigned val = 0; core->readRegister(core, name, &val); return val;
}
void dump(unsigned a, unsigned n, unsigned char *out) {
  for (unsigned i = 0; i < n; ++i) out[i] = core->busRead8(core, a + i);
}
void image(unsigned char *out) { memcpy(out, pixels, sizeof(pixels)); }
unsigned state_size(void) { return core->stateSize(core); }
int save(unsigned char *out) { return core->saveState(core, out); }
int load(unsigned char *in) { return core->loadState(core, in); }
unsigned color_size(void) { return sizeof(color_t); }
void stop(void) { core->deinit(core); core = NULL; }
