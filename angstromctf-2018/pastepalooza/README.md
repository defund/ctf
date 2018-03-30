The object of this challenge is to print the flag located in `mix.exs` on the server. The relevant code is within `utility.ex`:

```elixir
defmodule Utility do

  def access(filename) do
    unsafe = "pastes/" <> filename <> ".txt"
    path = filter(unsafe <> <<0>>, "", String.length(unsafe))
    case File.read path do
      {:ok, content} -> content
      {:error, reason} -> "File not found.\n"
    end
  end

  def filter(<< head, tail :: binary >>, acc, n) do
    if n == 0 do 
      acc
    else
      n = n - 1
      if head < 33 or head > 126 do
        filter(tail, acc, n)
      else
        filter(tail, acc <> <<head>>, n)
      end
    end
  end
end
```

Firstly, notice that the service has a local file inclusion vulnerability; it does not have to read from the `pastes/` directory. However, it does append a `.txt` file extension. It then runs the `filter` function to remove any bytes with ASCII values outside of the 33-126 range.

The bug in the code is that `String.length` returns the length of a Unicode string, while filter works byte by byte. If our filename has emojis, for example, it will prevent `filter` from reaching the `.txt`, effectively removing the file extension. `filter` will also remove the emoji bytes, thus leaving us with any filename. Thus, a valid payload would be `../mix.exs😀😀😀`