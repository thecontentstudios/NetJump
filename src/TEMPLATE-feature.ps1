# =============================================================================
# src/NN-feature-name.ps1 — TEMPLATE for new NetJump features
# =============================================================================
# When you add a new feature to NetJump, copy this file as
# src/NN-short-feature-name.ps1 where NN sets the load order (see src/README.md).
# Write the feature here, then either:
#
#   A) For NEW features (no existing main-file code to merge):
#      Add a single dot-source line at the end of NetJump-Dashboard.ps1:
#        . "$PSScriptRoot\src\NN-short-feature-name.ps1"
#      The feature loads on every script run. Build-NetJump.ps1 still works.
#
#   B) For MIGRATING an existing in-line section:
#      1. Move the code here.
#      2. Replace the in-line section in NetJump-Dashboard.ps1 with a single
#         dot-source line (same as A).
#      3. Run Build-NetJump.ps1 -SmokeTest to confirm parse + headless still pass.
#
# The build script concatenates src/*.ps1 in lexical order, so file naming
# matters. See src/README.md for the canonical numbering scheme.
# =============================================================================

# ---- State (if needed) ------------------------------------------------------
# $script:MyFeatureState = @{ ... }
# $script:State | Add-Member -NotePropertyName MyFeatureJob -NotePropertyValue $null -Force

# ---- Pure functions (preferred — easy to unit-test) -------------------------
# function Get-MyFeatureSomething {
#     param([Parameter(Mandatory)] $Input)
#     # ...
#     return $result
# }

# ---- Side-effecting functions ----------------------------------------------
# function Invoke-MyFeatureAction {
#     [CmdletBinding(SupportsShouldProcess)]
#     param([Parameter(Mandatory)] $Target)
#     if (-not $PSCmdlet.ShouldProcess($Target, 'My action')) { return }
#     # ...
# }

# ---- Tick hook (if the feature needs periodic work) -------------------------
# Add a call from the Tick function in NetJump-Dashboard.ps1:
#   try { Drain-MyFeatureEvents } catch {}
# Drain functions should be cheap (no-op if nothing to do) and self-throttling.

# ---- UI wiring (if the feature has UI controls) -----------------------------
# WPF wiring still lives in NetJump-Dashboard.ps1 (the big XAML block). For
# now, declare control names in the XAML and add handlers in the main file
# that delegate to functions defined here. Pure XAML splits are future work.

# ---- Cleanup at shutdown ----------------------------------------------------
# If the feature registers events, opens sockets, or starts jobs, add a
# matching teardown in the Window.Closed handler at the bottom of the main file.
