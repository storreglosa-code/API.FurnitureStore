using API.FurnitoreStore.Share;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace API.FurnitoreStore.Application.Interfaces;

public interface IProductCategoriesService
{
    Task<IEnumerable<ProductCategory>> GetAllAsync();
    Task<ProductCategory> GetByIdAsync(int id);

    Task CreateAsync(ProductCategory productCategory);

    Task UpdateAsync(ProductCategory productCategory);

    Task DeleteAsync(int id);

}
