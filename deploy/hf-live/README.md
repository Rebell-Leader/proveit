---
title: ProveIt live
emoji: ✅
colorFrom: gray
colorTo: green
sdk: gradio
sdk_version: 6.30.0
python_version: "3.12"
app_file: app.py
pinned: false
license: apache-2.0
short_description: Live mode for ProveIt, checking AI bug reports
---

# ProveIt: live mode

Checks AI-generated security reports against curl's real source code. This Space runs the full app: judge mode for
197 evaluated curl reports, and live mode, which calls NVIDIA Nemotron 3 Nano and Ultra on Nebius Token Factory
(the models do not run on this Space's GPU).

Source code, method and results: https://github.com/Rebell-Leader/proveit
