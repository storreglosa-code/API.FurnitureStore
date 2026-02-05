using System.Collections.Generic;
using System.Threading.Tasks;
using API.FurnitoreStore.Share;

namespace API.FurnitoreStore.Application.Interfaces
{
    public interface IProductsService
    {
        Task<IEnumerable<Product>> GetAllAsync();
        Task<Product?> GetByIdAsync(int id);
        Task CreateAsync(Product product);
        Task UpdateAsync(Product product);
        Task DeleteAsync(int id);
    }
}