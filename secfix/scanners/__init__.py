"""Live scanner API clients (Black Duck SCA, Fortify SAST).

These call the *real* vendor REST APIs and return the same raw report dicts the
offline sample files use, so `secfix.normalize` handles them unchanged. Zero
third-party deps — standard-library urllib only.
"""
