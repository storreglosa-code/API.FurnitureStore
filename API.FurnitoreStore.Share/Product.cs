using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace API.FurnitoreStore.Share;

public class Product
{
    public int Id { get; set; }

    public string Name { get; set; }

    public decimal Price { get; set; }

    public int ProductCategoryId { get; set; }

    [JsonIgnore]
    public List<OrderDetail>? OrderDetails { get; set; }

    [JsonIgnore]
    public List<ProductImage>? Images { get; set; }
}
