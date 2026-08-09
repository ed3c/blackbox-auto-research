# Experiment ledger

The ledger is append-only evidence. A `keep` decision requires a result that improves in the declared direction. A `discard` decision preserves the failed hypothesis and measured result so later iterations do not repeat it.

No-progress counts consecutive iterations that did not produce an accepted improvement. Reaching the configured threshold stops the loop and surfaces the best-known artifact.
