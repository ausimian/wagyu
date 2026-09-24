defmodule Wagyu.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/ausimian/wagyu"

  def project do
    [
      app: :wagyu,
      version: System.get_env("VERSION_OVERRIDE", @version),
      elixir: "~> 1.18",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases(),
      package: package(),
      source_url: @source_url,
      test_coverage: [tool: ExCoveralls],
      docs: [source_ref: @version, source_url: @source_url]
    ]
  end

  def cli do
    [preferred_envs: [precommit: :test]]
  end

  def application do
    [
      extra_applications: [:logger],
      mod: {Wagyu.Application, []}
    ]
  end

  defp deps do
    [
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:decibel, ">= 1.1.1 and < 2.0.0"},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false},
      {:excoveralls, "~> 0.18", only: :test},
      {:publisho, "~> 1.0", only: :dev, runtime: false},
      {:smolnet, "~> 0.4"}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_env), do: ["lib"]

  defp aliases do
    [
      precommit: ["compile --warnings-as-errors", "deps.unlock --unused", "format", "credo --strict", "test"],
      release: ["deps.get", "compile", "release"]
    ]
  end

  defp package do
    [
      description: "A supervised Elixir application.",
      files: ~w(.formatter.exs CHANGELOG.md LICENSE README.md lib mix.exs),
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url}
    ]
  end
end
