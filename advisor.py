from security_audit import (  # noqa: F401
    FALLBACK_ADVICE,
    RULE_SEVERITY,
    generate_roadmap_fallback,
    is_ollama_available,
    main,
    query_ollama,
    run_audit,
)


if __name__ == "__main__":
    raise SystemExit(main())
